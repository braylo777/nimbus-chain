# NIMBUS

**A Dual-Path Byzantine Fault Tolerant Consensus Protocol for Certified Operations Tapes, with Verifiable Commitment to Autonomous Agent State**

*The Blockchain for Safe Superintelligence.* · N·I·M·B·U·S — Neural Inference Model for Blockchain Unforgeability in Securities

Published by Brandon “Braylo” Lopez — Founder, CEO

NimBros PBC · Working Draft V3 · Not submitted · Not investment advice

---

> **ABSTRACT.** NIMBUS certifies an ordered operations tape — and, by the same mechanism, autonomous-agent state transitions — with a dual-path BFT protocol in which a single-round fast path (4/5 quorum) races a two-chain slow path (2/3). **Safety.** At Byzantine stake f < 1/3, no two certificates bind distinct roots at one slot (Theorems A, B), by a reduction that is lossless in the hash term (Theorem A\*); under an eighteen-domain SHA-384 registry (Lemma 9″) forgery at 2^80 work succeeds with probability ≤ 2^−225, ≈2^−144 against a quantum adversary. Pipelined slots are safe under a vote lock and live under timeout-certificate recovery when 2q > n + 3f (Theorems A′, A″); censorship delay is geometric and deviation is deterred iff δ ≥ 1 − Rp/(G − S). **1 ms architecture.** BLS aggregation cannot meet 1 ms for any n (Proposition L); per-vote Ed25519 on arrival, streaming Merkle roots, three concurrent proposers and fast skip certificates can. Monte Carlo driven by natively measured, in-place costs gives end-to-end p99 ≤ 1 ms across an ≈78 km metro for 21 validators (≈84 km at n = 100 with n/6 verification cores), with order-book ordering final within 70 / 50 / 40 km at 0 / 2 / 4 crashed validators; state roots are deferred to 32 ms epochs, capping throughput at ≈4 × 10⁶ ops/s on 16 hashing cores (Proposition X). A light client proves any past operation final with 3.8 KB in 1.1 ms (Propositions V, W). A reference engine (nimbus-core v0.17: admission, quorum-replicated journal over authenticated TCP, matching with exact integer fees, signed taker and maker receipts, bridge settlement against validator-certified checkpoints) sustains 150–183 × 10³ signed entries/s on 4 cores with one fsync per slot and cross-slot pipelining; its replay reproduces every signed checkpoint bit for bit (Proposition Z); every fill charges each side ⌈n·b/10⁴⌉, stated in both receipts, a bid's lock provably covers every fill and fee, splitting an order never lowers its fee, and supply is conserved exactly (Proposition Z5); a forged receipt is accepted with probability ≤ Adv_EUF-CMA + 2^−225 at 2^80 work (Corollary Z1), and a checkpoint no honest validator re-derived is certified with probability ≤ (n − f)·Adv_EUF-CMA + 2^−128 + 2^−225 (Proposition Z‴) — the certifiers that make this hold re-execute the replicated journal at the engine's rate and co-sign at most one checkpoint per slot, across restarts (Corollary Z6). Acknowledging an order within 1 ms at p99 further requires Δ_slot = 0.25 ms, a durable flush ≤ 50 µs (Proposition Z′), verification workers that never sleep — waking a thread pool costs ≈365 µs per slot and leaves no capacity, spinning workers cost ≈64 µs and leave 43 / 121 / 279 entries/ms on 4 / 16 / 64 cores — and, with two replicas both required at 150 entries/ms, replicas within ≈10 km, or ≈23 km with windowed replication (Proposition Z⁗) — ≈22 km once authenticating a hop costs 30 µs (HMAC) and ≈14 km at 176 µs (Ed25519); polled, never-sleeping replication I/O measured 114 µs per hop on a shared VM, ≈18 km (§6.6). Every CPU and kernel component is measured within 4–10% of the model; the multi-machine network is not, and Appendix C specifies the seventeen hardware tests that would confirm or refute the latency claims.

**Keywords —** Byzantine Fault Tolerance; State Machine Replication; Threshold/Aggregate Signatures; Merkle Commitments; Dual-Path Consensus; Verifiable Agent-State Commitment

## At a Glance

Every headline result, where it lives, and how strong the evidence is. "Proved" = formal proof in this paper; "Simulated" = Monte Carlo of the stated model; "Measured" = timed on production libraries; "Open" = not yet established.

| Result | Where | Evidence | Status |
|---|---|---|---|
| Theorems A, A\*, B — root binding at f < 1/3; dual-path uniqueness at ≥ 4/5 live-honest stake; hash reduction lossless | §4.1 | Proofs + 300,000-trial adversarial fuzz, 0 violations | Proved |
| Forgery ≤ 2^−225 at 2^80 work (≈2^−144 quantum) under an eighteen-domain SHA-384 registry (nine consensus, nine engine) | §3.1, §4.1, B.1 | Cor. 13′, Props. Q, Q′; Lemmas 9, 9′, 9″, 9‴; extractors 48/48, 36/36, 36/36; registry 200,000/200,000 per domain group; 12/12 engine vectors parsed from the code | Proved |
| Light-client proof of any past operation: 3,789 B, verified in 1.09 ms on one core | §4.1 | Props. V, W; built and timed; accumulator extractor 20/20 | Measured |
| Censorship delay geometric (p99 160 ms at f → 1/3); deterrence iff δ ≥ 1 − Rp/(G − S) | §4.2–4.3 | Prop. 14′, Cor. 25C + MC (Figs. 1–2) | Proved |
| Pipelining: vote lock safe; TC recovery safe and live when 2q > n + 3f | §4.5 | Thms. A′, A″ + fuzz, 0/2,400 violations (Fig. 4) | Proved |
| 32 ms baseline: p50 51 ms, p99 67 ms; liveness cliffs at 4/5 and 2/3 | §6.1 | 20,000-slot MC (Fig. 5) | Simulated |
| BLS aggregates cannot reach 1 ms for any n; per-vote Ed25519 (0.063 ms) can | §6.4 | blst / libsodium + Prop. L (Fig. 7) | Measured |
| Streaming SHA-384 Merkle root: RFC 6962-exact, 5.2 µs tail at 16 cores | §6.4 | Props. R–R″; 1,224-case check; event sim | Proved |
| End-to-end p99 ≤ 1 ms across an ≈78 km metro (n = 21; 81 km at microbenchmark costs), ≈84 km at n = 100 with k ≈ n/6 cores | §6.4 | Composite MC (Fig. 8) | Simulated |
| Crashed leaders: K = 3 proposers + skip certificates; ordering p99 ≤ 1 ms within 70 / 50 / 40 km at b = 0 / 2 / 4 | §6.4 | Props. T, U + MC, 2 seeds at edges (Fig. 9) | Simulated |
| State root deferred to 32 ms epochs: ≈4.0–4.4M ops/s sustained on 16 SHA-384 cores (batch + state roots); per-slot roots would need 86 | §6.4, D.10 | Prop. X; native C root update matches within 10%; LOB 43.5 ns/op | Measured |
| Data-centre outage: fast path survives iff ≥ 6 sites; 7 sites hold 1 ms within ≈62 km | §6.4 | Prop. S + MC | Simulated |
| Post-quantum signatures at 1 ms: ML-DSA-44 to n ≤ 52; SLH-DSA infeasible | §6.4, D.2 | FIPS 204/205 timings + Prop. L | Measured |
| Companion hash retired: v1 invertible; v2 ⟺ DLP, not collision resistant | App. A | Proofs + executed attacks (Figs. 10–11) | Resolved |
| Prototype P0/P0-U/P0-TC: 0 conflicts in 295,500 outcomes incl. 16,000 skip certificates and 2,292 TC anchors, 0 unresolved with the fallback; in-place crypto 1.27× microbenchmarks (costs 3–4 km); pinning cuts p99 2.1–2.3× | §6.5 | Executed with emulated lognormal network; model on same host | Measured |
| Fast-path robustness: fallback 0 / 0.05 / 1.3% at b = 0 / 2 / 4; host stalls cost the b = 4 edge 5 km; quorum slack (n = 31) moves it to 45 km | §6.4, D.11 | Props. U, Y + stall meter + MC | Simulated |
| Reference engine: 150–183 × 10³ signed entries/s on 4 cores, durable per slot, pipelined across slots; taker and maker receipts with exact fees; quorum-replicated journal (blocking or windowed, authenticated TCP) with failover; bridge pays only under checkpoints co-signed by certifiers that re-execute the replicated journal; replay reproduces every signed checkpoint | §6.6 | nimbus-core v0.17, 120 tests; Props. Z5, Z7–Z9, Z‴; Cor. Z6; Cors. Z2, Z3; Props. Z, Z″; Cor. Z1; differential tests against sequential references | Measured |
| Engine acknowledgement p99 ≤ 1 ms needs Δ_slot = 0.25 ms, a ≤ 50 µs durable flush and never-sleeping verification workers: with the measured dispatch cost 43 / 121 / 279 entries/ms on 4 / 16 / 64 cores (zero-cost model: 68 / 220 / 351; sleeping thread pool: 0 / 0 / 0) | §6.6 | Prop. Z′ + MC on measured batch and dispatch costs; this VM's flush (p50 0.65 ms) fails | Simulated |
| Pipelined finality for f ∈ [n/5, n/3); replication hop on dedicated hosts (O28, T17); hardware testbed (seventeen acceptance tests specified) | §4.5, App. C | — | Open |

## 1 · Introduction & Problem Statement

### 1.1 Context

Certified operations tapes bind ordered trading actions (place, cancel, amend, transfer, liquidate) cryptographically. NIMBUS targets tapes written primarily by autonomous agents, at latencies where finality is a binding constraint. Horizon 0: Sui, ≈390 ms documented finality. Horizon 1 (this specification): purpose-built L1, 60–160 ms target under §2/§5's assumptions. §3 extends the tape's certification mechanism to agent state transitions directly.

### 1.2 Latency/Liveness Tradeoff

PBFT/HotStuff-lineage BFT: 2/3 quorum, live under f<1/3, multi-round latency (proposal→vote1→vote2) every slot regardless of network behavior. Single-round protocols (Votor, Alpenglow): one round at 4/5 quorum, no liveness below that threshold. NIMBUS races both per slot, first valid certificate wins (§3.2) — slow-path liveness unconditional (Theorem A), fast-path latency conditional on Theorem B's 4/5-live-honest hypothesis.

### 1.3 Contributions

- **Safety.** Root binding at f < 1/3 with a lossless hash reduction (Theorems A, A\*, B); forgery ≤ 2^−225 at 2^80 work, ≈2^−144 quantum, under an eighteen-domain SHA-384 registry (Cor. 13′, Props. Q, Q′; Lemmas 9, 9′, 9″).
- **Liveness and incentives.** Geometric censorship delay (Prop. 14′); deterrence threshold δ\* = 1 − Rp/(G − S) (Cor. 25C); pipelined safety and recovery when 2q > n + 3f (Theorems A′, A″).
- **1 ms architecture.** Per-vote Ed25519 on arrival (BLS cannot reach 1 ms, Prop. L), streaming Merkle roots (Props. R–R″), K = 3 concurrent proposers (Prop. T) and fast skip certificates (Prop. U): simulated end-to-end p99 ≤ 1 ms across an ≈78 km metro, to n = 100, ordering-final within ≈40 km with four crashed validators.
- **Reference engine.** Admission, quorum-replicated journal, matching, taker and maker receipts and bridge settlement in Rust: 150–183 × 10³ signed entries/s on 4 cores, replay-deterministic checkpoints (Prop. Z), receipt soundness (Cor. Z1), safe cross-slot pipelining (Prop. Z″), certified settlement (Prop. Z‴), replica durability and reach (Prop. Z⁗), in-order windowed release (Cor. Z2), exact fee accounting (Prop. Z5), certifiers that re-execute and co-sign (Cor. Z6), and a latency floor for acknowledging a trade (Prop. Z′), with the model's dispatch term measured and corrected (§6.6).
- **Negative results.** Companion hash candidates retired (App. A); SLH-DSA cannot meet 1 ms; three non-results on alignment (§4.4).

## 2 · System Model & Preliminaries

### 2.1 Network Model

> **PARTIAL SYNCHRONY (Dwork–Lynch–Stockmeyer).** There exists an unknown Global Stabilization Time Δ such that, after Δ, message delay between honest parties is bounded by a known constant Δ_round; before it, delay is unbounded and adversarially scheduled. Actual delay is written δ.

⚠ **TOPOLOGY.** §6.2's 60–160 ms envelope assumes a colo clique (Kₙ mesh, n∈{21,64}) — a scope limit, not a target validator-count claim. WAN topology/peer discovery: unspecified (O15).

### 2.2 Adversary Model

> **THREAT CLASS.** Byzantine: adversarial validators may deviate arbitrarily, not merely by crashing (contrast Crash-Fault-Tolerant models, which NIMBUS does not assume).

**Corruption threshold:** s(B)≤f<1/3 (Theorem A). **Liveness condition:** Theorem B requires ≥4/5 live-honest — offline honest ≠ corrupted; distinct failure modes. **Power:** PPT (Forge(λ), Def. 12), not information-theoretic.

⚠ **STATIC/ADAPTIVE — UNSPECIFIED.** Reductions are naturally static. Adaptive corruption: not claimed (O14).

### 2.3 Cryptographic Primitives

> **HASH FAMILY.** Hκ:{0,1}\*→{0,1}^λ, a keyed hash family assumed collision-resistant (Conjecture 1), instantiated as SHA-384 (λ = 384; Proposition Q′), with SHA-256 figures kept for comparison — *not* the companion prime-structured one-way-function candidate of Appendix A, retired after neither variant proved collision resistant (Propositions E, I; O7).

> **AGGREGATE SIGNATURES.** Σ, an aggregate signature scheme assumed EUF-CMA (existentially unforgeable under chosen-message attack), instantiated as BLS12-381 aggregate signatures, targeting a ~1 KB certificate size (§3.3). A vector of per-validator Ed25519 signatures may substitute without changing Theorem A (Proposition K, §6.4).

> **SIGNATURE RULE (reference engine).** Every Ed25519 signature the engine checks — client orders and actions, bridge operations, feed attestations, validator votes, checkpoints — is verified under the cofactored equation [8][s]B = [8]R + [8][k]A with canonical s (ZIP-215 [27]; RFC 8032 permits either equation [26]), and every public key must decode, be canonically encoded and not be of small order. Under this rule a randomized batch accepts exactly when every member verifies singly, except with probability ≤ 2^−128 per batch; under the cofactorless rule it does not (executed: a key-holder-crafted signature with an order-8 component in R is rejected singly and accepted by some batches). Small-order keys are excluded because under them R = identity, s = 0 verifies for every message (executed against the v0.3 engine: an order admitted with no private key).

⚠ **NOT USED.** No zk-SNARK, VDF, or polynomial commitment (KZG). Finality rests entirely on Theorem A's CR+EUF-CMA reduction.

## 3 · Protocol Architecture & Core Mechanism

### 3.1 State Machine Representation

> **BATCH & ENCODING (corrected in v3.3 — see Appendix B).** A batch B=(op₁,…,opₘ) is an ordered tuple from the alphabet {place, cancel, amend, IOC, FOK, transfer, deposit, withdraw, liquidate, funding, oracle_tick}; encode is injective into {0,1}^≤ℓ. Leaf digest: Hκ(0x00 ∥ encode(opᵢ)); internal node over λ-bit children a, b: Hκ(0x01 ∥ a ∥ b); root(B) = MTH(B), the unpadded RFC 6962 tree split at the largest power of two below m [23]. Header for proposer rank j: h_{t,j} = Hκ(0x02 ∥ t ∥ j ∥ root(B_{t,j}) ∥ h_prev ∥ A_{t−L}), where A is the history accumulator of Proposition W (leaf 0x04, node 0x05) over all headers certified by slot t − L; a skipped (t, j) binds r_⊥ = Hκ(0x03 ∥ t ∥ j); the state trie uses 0x06/0x07 (Proposition X); a timeout statement is signed over Hκ(0x08 ∥ t ∥ j ∥ reported vote). The nine prefixes are required for Lemmas 9, 9′ and Propositions U, W, X: without them, distinct batches, chains, skips, histories or states share a digest with no hash collision, and a signature of one message type verifies as another.

γ(S,B)→S′: deterministic application of batch B to book state S, price-time priority. Guarantee: every honest replica computes the same γ(S,B) given the same (Ct,B) — determinism and replica agreement, not a full operational semantics for γ.

> **DEFINITION 15 — AGENT STATE COMMITMENT.** Let an autonomous agent occupy a state Aₜ at slot t from some encodable state space. NIMBUS computes a commitment Cₜ=Hκ(Aₜ) and certifies (t,Cₜ) using the identical γₛ/γf machinery of §3.2 — the same certificates, the same Theorem A/B guarantee, applied to agent state instead of batch roots. A transition is admissible if it additionally satisfies a published predicate R(Aₜ,Aₜ₊₁) — a capability cap, spend limit, or action whitelist — checked before certification, not after.

### 3.2 Consensus Mechanism

A proposal for slot t is π=(t, parentQC, root, leader). Two certificate types compete for that slot; the first to become valid wins:

> **SLOW CERTIFICATE γₛ.** A Σ-aggregate of votes Qₛ with s(Qₛ)≥2/3 on π, plus a HotStuff-2 child QC (two-chain, published construction: Malkhi–Nayak, ePrint 2023/397 — not reproved in this draft).

> **FAST CERTIFICATE γf.** A Σ-aggregate of votes Qf with s(Qf)≥4/5 on π, produced in a single round (Votor pattern).

γ is valid only if it verifies, meets its stake threshold, and no essential signer is slashed for equivocation at t. Leader selection is VRF-based, known several slots ahead; the censorship window is one slot, restored by next-leader inclusion lists (Proposition 14, §4.2) with no additional happy-path vote round.

```
# PSEUDOCODE (illustrative, not a reference implementation)
for each slot t:
  leader ← VRF_leader(t) # known several slots ahead
  π ← leader.propose(t, parentQC, root(B_t))
  spawn: γf ← collect_votes(π, threshold=4/5, rounds=1)
  spawn: γₛ ← collect_votes(π, threshold=2/3, rounds=2) # HotStuff-2 two-chain
  γ ← first_valid(γf, γₛ) # race; either may win
  if no valid γ within Δ_slot:
    next_leader.inclusion_list ← ops_omitted(B_t) # liveness fallback, Prop. 14
  commit(γ) ⇒ Ct ← Ct₋₁ ∥ B_t
```

A certified prefix Ct is the unique genesis-rooted chain of batches whose certificates are valid. Certificate size target ≈1 KB (BLS12-381 aggregate); votes never occupy batch space.

### 3.3 Data Availability & Storage Layer

384 KB batch, rate-3/2 erasure coding (Turbine-style) → 576 KB coded shreds. At 10 Gbps: serialization <0.5 ms; tail RTT dominates t_dissem. No KZG or other DA-sampling commitment used.

## 4 · Formal Security Proofs & Game-Theoretic Analysis

### 4.1 Safety Proof (Consistency)

Two supporting quorum-intersection lemmas precede the main theorem.

> **LEMMA 5.** s(Q)≥2/3 and s(Q′)≥2/3 ⇒ s(Q∩Q′)≥1/3.

> *Proof.* s(Q)+s(Q′)−s(Q∩Q′)≤1 ⇒ s(Q∩Q′)≥4/3−1=1/3. □

> **LEMMA 6.** s(Q)≥4/5 and s(Q′)≥2/3 ⇒ s(Q∩Q′)≥7/15>1/3.

> *Proof.* 4/5+2/3−1=7/15. □

> **LEMMA 7.** f<1/3 and s(Q)≥2/3 ⇒ s(Q∩(V∖B))>1/3. Every slow quorum contains honest stake.

> **DEFINITION 12 (Forge(λ)).** Challenger samples κ, Σ-keys, s. PPT adversary A corrupts B with s(B)≤f<1/3 and queries honest votes; honest keys never sign two proposals at one slot (a second request is logged as equivocation, not signed). A wins if it outputs two valid slow certificates for the same t with distinct roots, neither depending on an essential slashed key.

> **THEOREM A.** If Hκ is collision-resistant and Σ is EUF-CMA and f<1/3, then Adv_A^Forge(λ) ≤ negl(λ): two honest nodes never commit conflicting roots at the same slot.

> *Proof.* Let (γ,γ′) be a winning pair, proposals π,π′, roots r,r′. **Case r≠r′:** signer sets Q,Q′ have s≥2/3. Lemma 5 ⇒ s(Q∩Q′)≥1/3. Lemma 7 ⇒ the intersection meets V∖B. An honest v signed both π and π′ at t, contradicting the honest rule, or A forged a Σ-signature of v (EUF-CMA, negl). **Case r=r′, batches B≠B′:** Lemma 9 (§Appendix B) ⇒ collision in Hκ (CR, negl). **Case parent pointers differ:** recurse on slot t−1; base case is the unique genesis. A union bound over poly(λ) slots remains negligible. □

> **THEOREM A\* (concrete form; the hash term is lossless).** Let A run in time τ over s slots of ≤ m operations. Then Adv^Forge(A) ≤ Adv^CR_H(B₁) + n·Adv^EUF-CMA_Σ(B₂), where B₁ runs in time τ + 2s(2m − 1)·t_H and B₂ in time τ + O(q_sig·t_sign), q_sig the signing queries A makes.

> *Proof.* The three cases of Theorem A partition every winning run. B₁ runs A; on a Case r = r′ win at any slot of the recursion it recomputes both trees (≤ 2(2m − 1) hashes per slot, ≤ s slots) and returns the Lemma 9 collision, which exists with probability 1 — no guessing, so no loss. B₂ samples v ← V, embeds the EUF-CMA challenge key as v's key, generates all other keys, answers A's queries, and on a Case r ≠ r′ win returns v's signature on the proposal v never signed; v lies in the honest intersection with probability ≥ 1/n. Summing the cases gives the bound. □

Numerically (λ = 384, 10 years of 1 ms slots, s = 2^38.2, m = 4,096): the extractor adds 2^52.2 hash evaluations to A's q = 2^80, changing q²/2^385 by a factor (1 + 2^−27.8)² — the Corollary 13′ bound is unchanged. The only reduction loss is the factor n = 21 (≈2^4.4) on the signature term.

> **THEOREM B (dual-path extension).** Under Theorem A's hypotheses, if in slot t at least 4/5 of stake is live and honest, then a valid γf and a valid γₛ cannot bind distinct roots at t, except with negligible probability. If the live-4/5 condition fails, root uniqueness reduces to the slow-path statement of Theorem A alone — the fast path simply does not produce a certificate.

> *Proof.* Distinct roots ⇒ signer sets Qf, Qₛ. Lemma 6 ⇒ s(Qf∩Qₛ)≥7/15>1/3. Live-honest 4/5 ⇒ the intersection contains honest stake that did not sign two roots. Otherwise reduce to EUF-CMA or CR as in Theorem A. If 4/5 is not live, γf is not produced and Theorem A applies directly. □

> **COROLLARY 13.** Rewriting one fill in a certified batch requires a collision of Hκ, a forgery of Σ, or s(B)≥1/3 — i.e., breaking one of this section's core assumptions.

> **THEOREM C (typed kernel).** Let (Ct) be the certified-prefix process and y_(t+Δ) an exogenous outcome in a Polish space. If Φ:Cert→ℝᵏ is Borel, a regular conditional p(y_(t+Δ)|Φ(Ct),D) exists. The kernel K(·|φ,D) is typed on φ∈Φ(Cert) only — Φ(R(local uncertified book)) is not a valid input by construction, not merely by convention.

A fuzz test, not a substitute for the proof above: does the quorum-intersection model Lemmas 5–7 state actually hold when an adversary picks stakes and quorum membership to try to break it?

> **COMPUTATIONAL SANITY CHECK (fuzz test, not a proof).** For n∈{4,7,10,21,64}, 20,000 trials each: random positive stake weights; a Byzantine set greedily packed to just under 1/3 of total stake; quorums Q, Q′ adversarially constructed to hit their threshold while avoiding overlap on honest members as much as possible. Checked: Lemma 5 (s(Q),s(Q′)≥2/3 ⇒ s(Q∩Q′)≥1/3), Lemma 6 (s(Q)≥4/5, s(Q′)≥2/3 ⇒ s(Q∩Q′)≥7/15), and Lemma 7 as used in Theorem A (f<1/3, s(Q)≥2/3 ⇒ Q contains an honest validator). Result: 0 violations in 300,000 adversarial trials — a check that the simulation code (§6.1, §6.4) implements the quorum model the lemmas prove, not additional evidence for them.

> **COROLLARY 13′ (concrete security, λ-bit hash).** The hash term of Theorem A is bounded by the birthday bound Adv_CR ≤ q²/2^(λ+1) for q total hash evaluations (λ = 384 specified, SHA-384; λ = 256 figures below for SHA-256 / BLAKE2b-256 comparison); the signature term is n·Adv_EUF-CMA(Σ), unchanged. Honest load over 10 years of 32 ms slots with 8,192 Merkle hashes per slot is ≈2^46.2 — negligible against the bound. Inclusion proofs: with domain separation, a forged proof for a leaf not in B yields a collision or a second preimage at some path node; against T target digests, generic search succeeds with probability ≤ qT/2^λ = 2^−130 (λ = 256; 2^−258 at λ = 384) at q = 2^80, T = 2^46.2 (32 ms slots); at 1 ms slots with m = 4,096, T = 2^51.2 and the bound is 2^−124.8 (Proposition Q).

| adversary hash budget q | λ = 256 (SHA-256) | λ = 384 (SHA-384, specified) | quantum Q³/2^λ, λ = 256 / 384 |
|---|---|---|---|
| 2^64 | 2^−129 | 2^−257 | ≈2^−64 / 2^−192 |
| 2^80 | 2^−97 | 2^−225 | ≈2^−16 / 2^−144 |
| 2^100 | 2^−57 | 2^−185 | ≈1 / 2^−84 |

**Hash commitments: concrete results** (statements, proofs and executed checks in Appendix B.2):

| result | bound / cost | where |
|---|---|---|
| Multi-target inclusion forgery, 10 years of 1 ms roots | ≤ qT/2^λ: 2^−124.8 (λ = 256), 2^−252.8 (λ = 384) | Prop. Q |
| Quantum collision term, Q = 2^80 | ≈ 2^−16 (λ = 256) → ≈ 2^−144 (λ = 384): SHA-384 specified | Prop. Q′ |
| Light-client finality proof, n = 21 | 1.77 KB; 17 signature checks + 13 hashes | Prop. V |
| History accumulator, 10 years | 40 siblings (1.92 KB) vs a 100 TB header walk | Prop. W |
| Complete proof for any past operation | 3,789 B; 1.09 ms on one core; 0/6,000 mutated proofs accepted | Measured |

### 4.2 Liveness (Informal)

⚠ **NOT A FORMAL PROOF.** Unlike §4.1, this subsection is not accompanied by a reduction to a hardness assumption. It states a design claim about leader rotation, not a theorem with a QED. A full liveness proof under the partial-synchrony model of §2.1 — analogous in rigor to Theorem A's safety proof — is not given in this draft. See Open Problem O10.

> **PROPOSITION 14 (liveness, not safety — stated as policy).** A Byzantine leader omits operations for at most one slot (Δ_slot). Next-leader inclusion lists restore liveness with no extra happy-path vote round.

> **PROPOSITION 14′ (censorship delay).** Proposition 14's one-slot bound holds per Byzantine leader, not per transaction. If honest validators refuse to certify a proposal that omits inclusion-list operations, an omitted operation lands at the first honest-leader slot. With VRF leaders and Byzantine stake fraction f, the delay D (slots) is geometric: P(D>k) = f^k, E[D] = 1/(1−f).

> *Proof.* Monte Carlo, 200,000 trials per row, worst-case adversary (every Byzantine leader censors): f=0.10 → E[D] 1.110 (exact 1.111), p99 2 slots (64 ms); f=0.20 → 1.249 (1.250), p99 3 slots (96 ms); f→1/3 → 1.501 (1.500), p99 5 slots (160 ms). MC matches the closed form in every row. □

*Figure 1. Censorship-delay survival curves for three Byzantine stake fractions (log scale). Lines are the closed form fᵏ; dots coincide with the 200,000-trial Monte Carlo.*

### 4.3 Incentives & Rational Adversary Model

> **DEFINITION 23 (rational validator).** A validator v with stake s(v) is rational if it chooses a signing strategy to maximize expected stake-weighted payoff over an epoch horizon, taking as given: a per-slot reward R for each valid vote contributed to a finalizing certificate (γₛ or γf); a slash of v's entire stake s(v) on proven equivocation (Definition 10); and a jail period J (no rewards, no voting rights) on a missed-vote pattern consistent with liveness fault. R, the slash fraction, and J are protocol parameters, not modeled quantities — Proposition 24 holds for any R>0 and any positive slash fraction, and gets strictly stronger as the slash fraction increases.

> **PROPOSITION 24 (honest signing is a best response).** For a rational validator v under Definition 23, honestly signing at most one proposal per slot weakly dominates equivocating, and strictly dominates it whenever the equivocation is detected with positive probability.

> *Proof.* Compare v's two available actions at slot t, holding all other validators' strategies fixed (a best-response argument, not a full equilibrium computation). **Honest:** v signs π once, receives R if its vote is part of a finalizing certificate, 0 otherwise. Expected payoff R·p, p∈[0,1] the probability v's vote lands in a finalizing quorum. **Equivocate:** v signs both π and π′≠π at t, hoping to double-collect R by landing in two different certificates. By Definition 10, a second signature from v at the same slot is logged as equivocation, not merely a second vote; by Theorem A's proof (case r≠r′), producing two valid certificates with distinct roots at t requires either an honest validator to have signed both — which v is not, since v is the deviator — or a CR/EUF-CMA break (negligible). So the realistic branch is: v's equivocation is detected (any honest full node observing both signed messages can exhibit the slashing proof — detection is a public-verification cost, not a consensus-level one, and is independent of whether either certificate finalizes). Detected with probability q>0 ⇒ expected payoff ≤ R·p·(1−q) − q·s(v). Since s(v)>0 and R is a fixed per-slot reward while s(v) is accumulated stake, s(v) ≫ R for any validator that has been staked more than a few epochs, so the equivocation branch's expected payoff is strictly below R·p for any q>0, and equal to it only in the degenerate q=0 case (equivocation is never detectable) — which Definition 10's public-logging rule is designed to exclude. □

> **COROLLARY 25.** Proposition 24 is a single-validator best response, the notion Theorem A needs (its adversary bound f < 1/3 is exogenous). It does not show that f < 1/3 is itself incentive-compatible: a coalition that expects to evade detection, or values extraction above its stake, is outside its scope. Deriving f < 1/3 from stake-acquisition cost is O11.

> **COROLLARY 25B (repeated game).** Validators interact across epochs. By the Folk Theorem [16], for discount factor δ sufficiently close to 1 any feasible, individually rational payoff — including sustained partial equivocation, censorship, or coordinated MEV extraction enforced by grim-trigger strategies — is a subgame-perfect equilibrium. Proposition 24 excludes only one-shot, single-validator deviation; whether R, S and J exclude these equilibria is O11, quantified in Corollary 25C.

> **COROLLARY 25C (the patience threshold, quantified).** Deviation payoff G at slot 0 (replacing that slot's Rp), stake slashed on detection S, then permanent exclusion (grim trigger). Cooperation is a best response iff Rp/(1−δ) ≥ G − S, i.e. δ ≥ δ\* = 1 − Rp/(G−S) for G > S+Rp, and δ\*=0 otherwise. Taking S=0 (pessimistic: ignores the slash) gives δ\* = 1 − Rp/G.

> *Proof.* Standard grim-trigger condition δ ≥ (T−Rw)/(T−P) with T=G−S, Rw=Rp, P=0. Verified by direct Monte Carlo of the discounted-payoff race (Bernoulli(p) vote inclusion, R=1, p=0.9, 6,000 trials, δ\*±0.03): E[PV(coop) − PV(defect)] changes sign exactly at δ\* for G ∈ {2,5,10,50}R, with δ\* = 0.550, 0.820, 0.910, 0.982 and MC advantage matching the closed form within ≈2 SE (e.g. G=10R: −2.507±0.008 vs exact −2.500 below; +5.004±0.011 vs +5.000 above). □

Consequence. With N slots per year and annual discount rate r, 1 − δ ≈ ln(1+r)/N, so a single validator deviates only if G > S + Rp·N/ln(1+r). At r = 10%: N = 9.9×10⁸ (32 ms) gives G > S + 1.0×10¹⁰·Rp; N = 1.3×10¹¹ (Δ_slot = 0.25 ms) gives G > S + 1.3×10¹²·Rp — faster slots raise the threshold 128× at equal per-slot reward, or leave it unchanged if Rp is scaled by Δ_slot to hold annual issuance fixed. Either way, a one-shot gain exceeding its stake plus the present value of all future rewards. Individual impatience is therefore not the live risk; three things are: (i) **coalitions** sharing a collusive G across epochs (Corollary 25B's multi-player equilibria); (ii) **G large relative to S** for small-stake validators facing a large extractable opportunity; (iii) the **end game** — a validator planning to exit has a finite horizon, the repeated-game deterrent unravels by backward induction, and only S remains, which bites only if the unbonding delay exceeds the equivocation-evidence window. O11 sharpens to: size S and the unbonding delay against the largest extractable G.

*Figure 2. Corollary 25C: critical discount factor δ\ against one-shot deviation gain G. Shaded region: cooperation is a best response. Dots: δ\ values where the Monte Carlo expected advantage changes sign.*

⚠ **STILL NOT ANALYZED.** MEV extraction from leader ordering power; long-range revision beyond Theorem A's certificate-chain recursion; Sybil resistance beyond §2.2's stake-weighted assumption; repeated-game collusion under Corollary 25B's folk-theorem regime. O12–O13.

### 4.4 Agent-State Guarantees and Their Limits

> **PROPOSITION 17 (auditability).** Under Theorem A's hypotheses, every agent state transition under NIMBUS admission control is (i) bound to a unique commitment, (ii) totally ordered and unforgeable, (iii) checked against predicate R pre-certification, with rejections themselves certified. Consequence: any harm an agent causes traces to an exhibitable, verified transition Aₜ→Aₜ₊₁ and a record of whether R permitted it — regardless of whether the agent is aligned.

> *Proof.* Immediate from Corollary 16 and Definition 15: R is evaluated pre-certification by construction; the certified sequence cannot be altered post hoc without breaking Theorem A. □

> **COROLLARY 18 (bounded harm, conditional).** If R bounds every admissible transition's loss by M (e.g. a fixed per-transition spend cap or position-size limit), total loss from one certified agent between interventions ≤ (transitions before detection) × M. Detection latency, not record integrity, becomes the binding constraint.

**Non-result 19.** Nothing constrains the policy selecting Aₜ→Aₜ₊₁ among admissible transitions; R certifies action-within-bounds, not intent, not objective. **Non-result 20.** A capable misaligned policy can satisfy R while pursuing an objective R was never designed to detect. **Non-result 21.** Corollary 18's bound is conditional on R and detection latency, both external to the cryptography; a loose R or slow human loop reproduces an unconstrained system with better bookkeeping.

> **STATEMENT 22.** NIMBUS does not claim a hash commitment solves alignment. The claim: verifiable state-transition commitment converts undetectable misalignment into detectable misalignment at the moment it acts, and makes R — not the model's stated intentions — the enforced boundary.

### 4.5 Pipelined Slots: Safety and the Liveness Gap

With Δ_slot < t_fin (§6.4), a validator voting at slot k knows certificates only up to slot k − L, L ≥ 1. Theorem A's case "parent pointers differ" assumes certified parents; pipelining removes that assumption.

> **RULE V (vote lock).** Honest validator v, with last vote ℓ_v, votes for π at slot k only if it has not voted at k and either (a) parent(π) = ℓ_v, or (b) parent(π) is a certified proposal known to v with slot(parent(π)) ≥ slot(ℓ_v).

> **THEOREM A′ (pipelined safety).** Under Theorem A's hypotheses and Rule V, for any lag L, the set of certified proposals is totally ordered by ancestry.

> *Proof.* Suppose not; among violating pairs (a, b) — slot(a)=i ≤ slot(b)=j, b not a descendant of a — take one with j minimal. If i = j, two certificates exist at one slot, excluded by Theorem A. If i < j, Lemmas 5 and 7 give an honest v ∈ Q_a ∩ Q_b. Let u₁ = a, u₂, …, u_t = b be v's votes from slot i on. By induction, each u_r descends from a: under (a) u_{r+1} extends u_r; under (b) it extends a certified c with i ≤ slot(c) < j, and c descends from a, since otherwise (a, c) is a violating pair with a smaller second slot than j. Hence b = u_t descends from a, a contradiction. Parent identity is by Hκ digest, unique under CR. □

**Model M2 (fuzz test).** n=21, 6 Byzantine, q=14, L=2, 60 slots, VRF leaders; Byzantine leaders choose proposals and parents, deliver them first to disjoint halves of the honest set, and choose their own votes. Three adversaries: *equivocate* (two proposals, Byzantine vote both), *fork* (certify one sibling, later extend the uncertified one), *split-and-withhold* (split honest votes between siblings, never vote). 1,500 runs per cell:

| rule | adversary | runs violating safety | slots certified | runs stalled (last 10 slots) |
|---|---|---|---|---|
| none | equivocate / fork | 1,500 / 1,500 each | 100% | 0 |
| lock on known certificate | equivocate | 1,161 / 1,500 | 97.5% | 0 |
| lock on known certificate | fork | 1,499 / 1,500 | 84.8% | 0 |
| Rule V | equivocate | 0 / 1,500 | 72.6% | 333 / 1,500 |
| Rule V | fork | 0 / 1,500 | 30.3% | 801 / 1,500 |
| Rule V | split-and-withhold | 0 / 1,500 | 4.4% | 1,500 / 1,500 |

> **PROPOSITION M (lock dilemma under lag).** With L ≥ 1, locking on the highest known certificate is unsafe (a sibling certified inside the lag window is invisible to the lock), while Rule V is safe (Theorem A′) but not live: after a split in which no sibling is certified, honest locks disagree and Byzantine withholding keeps every later proposal below q.

> *Proof.* Safety failure: certify π₂ at slot k with 8 honest + 6 Byzantine votes; π₁ holds 7 honest votes. A slot-(k+1) child of π₁ extends every lock that predates π₂'s certificate, so it gathers 15 + 6 ≥ q. Liveness failure: with honest locks split 7/8 between uncertified siblings, any later proposal satisfies Rule V for at most 8 honest validators, 8 < q = 14 without Byzantine votes. Both observed in M2 (table). □

*Figure 3. Model M2: safety violations (left) and certified-slot fraction (right) by lock rule and adversary.*

> **RULE V+ (timeout-certificate unlock).** If slot k has no known certificate by slot k + L, honest validators sign Timeout(k, ℓ_v). A timeout certificate T is t = n − f such messages; with τ = t − f − (n − q), anchor(T) is the deepest proposal x such that ≥ τ signers report a last vote descending from x. Rule V+ is Rule V plus clause (c): parent(π) = anchor(T) for a known T formed after v's last vote.

> **THEOREM A″ (safe recovery).** If 2q > n + 3f, Rule V+ preserves Theorem A′: certified proposals remain totally ordered for any lag L.

> *Proof.* Extend Theorem A′'s induction with clause (c): u_{r+1} extends anchor(T), T formed after u_r and hence after every vote for a. At least q − f honest validators voted a, so at most n − q honest did not; T has ≥ t − f honest signers, so ≥ τ of them voted a, and their reported last votes descend from a (induction on earlier votes). Thus a has support ≥ τ. Two incomparable proposals have disjoint supporter sets, so both reaching τ requires 2τ ≤ t; but 2τ > t ⇔ t > 2(n − q + f) ⇔ (t = n − f) 2q > n + 3f. The proposals with support ≥ τ therefore form a chain containing a, and anchor(T), its deepest element, descends from a. □

> **PROPOSITION N (liveness after GST).** If q ≤ n − f, every timed-out slot yields a timeout certificate from honest signers alone, every honest last vote predates it, and the next honest leader's child of anchor(T) is certified. For NIMBUS: single-certificate pipelining needs the fast quorum q = ⌈4n/5⌉ with f < n/5 (n = 21: f ≤ 4, q = 17 = n − f). The 2/3 quorum would need f < n/9, so the slow path keeps two-chain finality and is not pipelined this way.

> *Proof.* t = n − f honest timeouts form T; clause (c) then holds for every honest validator; q ≤ n − f honest votes certify. For q = 4n/5: 8n/5 > n + 3f ⇔ f < n/5; for q = 2n/3: 4n/3 > n + 3f ⇔ f < n/9. □

> **COROLLARY N1 (timeout calibration).** With per-slot cost C(Δ_to) = t_fin if t_fin ≤ Δ_to, else Δ_to + t_rec, and a fraction β of split-inducing Byzantine leaders, E[C] = (1−β)E[min-cost honest] + β(Δ_to + t_rec). Spurious timeouts force Δ_to ≥ the finality tail; attack cost grows linearly in Δ_to. Optimum: Δ_to ∈ [p99, p99.9] of t_fin.

| Δ_to | P(spurious timeout) | E[C], β = 0 | E[C], β = 0.19 (f = 4) |
|---|---|---|---|
| 0.9 ms | 35.9% | 1.197 ms | 1.310 ms |
| **1.0 ms** | 1.00% | 0.898 ms | **1.086 ms** |
| **1.1 ms** | 0.009% | **0.889 ms** | 1.098 ms |
| 1.5 ms | 0% | 0.889 ms | 1.174 ms |
| 3.0 ms | 0% | 0.889 ms | 1.459 ms |

10⁵ simulated slots at the 62.6 km operating point (p99 1.000, p99.9 1.052, max 1.179 ms; t_rec ≈ E[t_fin] = 0.889 ms). Set Δ_to ≈ 1.05 ms: below p99 spurious recoveries dominate; each 0.1 ms above p99.9 adds ≈0.019 ms expected cost per slot under attack.

**Model M3** — M2 plus timeout certificates (L = 2); the adversary chooses each certificate's composition and reports, and may certify a sibling while hiding the certificate. 600 runs per cell:

| configuration | rule | violations (4 adversaries) | slots certified | stalled runs |
|---|---|---|---|---|
| n=21, f=4, q=17 (2q > n+3f) | V | 0 / 2,400 | 6.6–61.5% | 2,076 / 2,400 |
| n=21, f=4, q=17 (2q > n+3f) | **V+** | **0 / 2,400** | **70.3–97.6%** | **0 / 2,400** |
| n=21, f=6, q=14 (2q ≤ n+3f) | V | 0 / 2,400 | 4.1–74.8% | 1,609 / 2,400 |
| n=21, f=6, q=14 (2q ≤ n+3f) | V+ | 1,316 / 2,400 | 59.5–98.1% | 0 / 2,400 |

Violations for 2q ≤ n+3f concentrate in the fork (600/600) and hidden-certificate (594/600) adversaries: with τ = 2 the anchor can land on the uncertified sibling. Under attack, each split costs ≈ L + 1 slots, giving the 70% floor.

*Figure 4. Model M3: Rule V+ restores liveness without violations when 2q > n + 3f and fails safety otherwise.*

## 5 · Tokenomics & Cryptoeconomic Design

> **BASIS.** Horizon 0/1 are one organization's infrastructure at two layers (§1.1). §5.2's rate is not proposed — it is the deployed Horizon-0 value, PLATFORM_FEE_BPS = 15. All other §5 figures are **candidates** pending sign-off, chosen for consistency with that one live number and §6.2's throughput figures.

### 5.1 Supply (candidate)

> **CANDIDATE 26.** Fixed supply at genesis, no protocol-level inflation — an inflating unit of account complicates §3.1's price-time, deterministic-fill guarantee. Exact supply, decimals, genesis allocation: unset. 9 decimals (Horizon-0 convention) is the default if cross-horizon consistency is wanted, not a derivation.

### 5.2 Fee Markets

PLATFORM_FEE_BPS = 15 (0.15%): deployed Horizon-0 rate, carried to Horizon-1 as one fee schedule across the Horizon-0→Horizon-1 migration.

> **CANDIDATE 27 (split — proposed).** Of 15 bps: majority → validators as reward R (Proposition 24 requires R>0); minority → treasury (funds O3/O5/O17); minority → an insurance reserve against a margin-breach halt. Ratios unset — pending sign-off.

Not specified: EIP-1559-style base-fee or multi-dimensional gas pricing for general execution.

### 5.3 Governance (candidate)

> **CANDIDATE 28.** Stake-weighted voting scoped to parameters already exposed as tunable — corruption-margin, R and the slash fraction (Def. 23), predicate R(Aₜ,Aₜ₊₁) (Def. 15) — not an open-ended proposal system, so a vote cannot invalidate Theorem A/B/C by changing what the proofs hold fixed. No quadratic voting; packages immutable (Horizon-0 convention), so "upgrade" means a new certified genesis, not a live mutation.

## 6 · Evaluation, Simulations, & Empirical Results

### 6.1 Monte Carlo Finality Simulation

> **MODEL M1.** Per slot, validator i's round-trip time is Rᵢ = Xᵢ + Yᵢ with Xᵢ, Yᵢ i.i.d. LogNormal(ln μ, σ²) (μ = one-way median); equal stake. With R_(k) the k-th order statistic, t_fast = t_dissem + R_(⌈0.8n⌉), t_slow = t_dissem + R_(⌈2n/3⌉) + R′_(⌈2n/3⌉) (independent second round, HotStuff-2 child QC), and t_fin = min(t_fast, t_slow), matching §3.2. t_dissem = 0.46 ms (App. B). Seeded, reproducible; a model evaluation, not a deployment (O3, O17).

| n | one-way median | σ | mean | p50 | p95 | p99 | fast-win rate |
|---|---|---|---|---|---|---|---|
| 21 | 18.0 ms | 0.50 | 51.4 ms | 51.0 ms | 61.4 ms | 66.8 ms | 100.0% |
| 64 | 18.0 ms | 0.50 | 52.6 ms | 52.4 ms | 58.5 ms | 61.4 ms | 100.0% |

20,000 slots per row. Median 51.0 / 52.4 ms lies below §6.2's 60–100 ms closed-form band, which assumes a worst-case tail; the Monte Carlo adds the distribution the closed form lacks.

*Figure 5. Simulated t_fin (n=21, μ=18 ms, σ=0.5) with p50 and p99 against §6.2's closed-form band.*

Raising σ from 0.2 to 1.3 at fixed median multiplies p99 by 3.9 (45.5 → 175.6 ms) and cuts fast-path wins to 78.5%; the 1 ms regime shows the same law (Appendix D.1).

**Live-stake degradation** (n=21, μ = 18 ms, σ = 0.5, 8,000 slots per row; offline validators silent, not Byzantine, per §2.2):

| live stake | fast-path rate | slow-path rate | stall rate | mean finality |
|---|---|---|---|---|
| 100% | 100.0% | 100.0% | 0.00% | 51.3 ms |
| 85% | 100.0% | 100.0% | 0.00% | 63.4 ms |
| 80% | 100.0% | 100.0% | 0.00% | 74.6 ms |
| 75% | 0.0% | 100.0% | 0.00% | 110.8 ms |
| 67% | 0.0% | 100.0% | 0.00% | 145.3 ms |
| 60% | 0.0% | 0.0% | 100.00% | never |

For n=21 the fast path requires ⌈0.8n⌉/n = 17/21 = 81.0% live stake and the slow path ⌈2n/3⌉/n = 14/21 = 66.7%; the simulated transitions fall exactly at these thresholds (Theorem B, Lemma 5), confirming the implementation matches the model. Below 4/5, p99 roughly doubles; below 2/3, liveness is lost (O4).

*Figure 6. Mean t_fin by live stake: fast path (blue), slow path only (amber), no quorum (hatched).*

### 6.2 Architectural Capacity Estimates (Not Measurements)

> **ENCODING CEILING.** ops/slot ≤ ⌊B_bytes/ℓ⌋. At 384 KB and ℓ=96 B: 4096 ops/slot. Slots/s = 1000/32 = 31.25. Ceiling = 4096×31.25 = 1.28·10⁵ ops/s. This is not a promised TPS figure — it bounds encoding capacity, not execution throughput, which is expected to be the binding constraint in practice.

> **PROPOSITION D (arithmetic, not measurement).** After GST, inside a colo clique: t_γf ≤ Δ_slot + t_dissem + t_vote1; t_γₛ ≤ Δ_slot + t_dissem + t_vote1 + t_vote2. Substituting stated component latencies gives 60–100 ms (fast path) / 100–160 ms (slow path). Not a WAN measurement.

**Clique cost:** Kₙ = n(n−1)/2 edges — 210 at n=21, 2016 at n=64; the decentralization cost of §2.1's latency SLA. **Geodesic:** c_f≈2·10⁸ m/s, NY–LON ≈5.57·10⁶ m ⇒ one-way ≈28 ms. Certificate time ≠ end-to-end client latency beyond this budget.

### 6.3 Comparative Structural Benchmark

Structural comparison only — quorum fraction and round structure, as publicly documented by each system. Not a throughput/latency benchmark: this draft has no measured figures of its own to compare (§6.1).

| System | Quorum (safety) | Rounds | Fast path | Finality (as documented) |
|---|---|---|---|---|
| PBFT (Castro–Liskov) | 2/3 | 3 | No | Deterministic, multi-round |
| HotStuff-2 | 2/3 | 2 (responsive) | No | Deterministic, two-chain |
| Alpenglow / Votor | 4/5 fast, 3/5 fallback | 1 (fast) | Yes | Sub-second (documented) |
| Hyperliquid HyperBFT | 2/3-class | — | No | Sub-second (per project docs) |
| Sui / Mysten | 2/3-class | — | No | ≈390 ms (documented) |
| NIMBUS (this draft) | 2/3 slow, 4/5 fast | 2 / 1 (race) | Yes, races both | 60–160 ms (estimate, §6.2) |

TPS-vs-node-count plots and time-to-finality-under-adversarial-load graphs require an actual or simulated deployment; producing them is Open Problem O3.

### 6.4 Sub-Millisecond Finality: Model, Bounds, Architecture

Model: t_fin = t_dissem + C_(q), where C_(q) is the completion time of the q-th vote verification (q = ⌈0.8n⌉ fast, ⌈2n/3⌉ per slow round); target p99(t_fin) ≤ T = 1 ms. Three constraints bind — propagation, verification, and the slot clock — each bounded below and each checked by Monte Carlo (n=21 unless stated, σ=0.3, 20,000-trial verification runs, Ed25519 service times from measured samples).

> **PROPOSITION F (propagation bound).** A one-way budget t_ow bounds validator separation by d ≤ c_f·t_ow, c_f ≈ 200 km/ms. Every distance in this section is 200 × (max one-way median). The NY–LON geodesic (≈28 ms one-way, §6.2) exceeds T by ≈147×; sub-millisecond finality therefore implies a single-metro validator set, kernel-bypass networking, and correlated-failure exposure (O18).

**Measured verification cost** (production libraries unless noted):

| scheme / library | sign | verify (1 sig) | aggregate-verify n=21 | n=64 |
|---|---|---|---|---|
| BLS12-381 / py_ecc (pure-Python reference) | 124–141 ms | 443 ms | 664 ms | 1,142 ms |
| BLS12-381 / blspy → blst | 0.45 ms | 1.48 ms | 1.40 ms | 1.46 ms |
| Ed25519 / PyNaCl → libsodium | — | 0.063 ms (p99 0.099) | — | — |

*Figure 7. Verification cost per call (log scale) against T = 1 ms.*

> **PROPOSITION K (Theorem A is agnostic to aggregation).** Replacing Σ by a vector of per-validator Ed25519 signatures plus a signer bitmap leaves Theorem A, Theorem B and Corollary 13 unchanged (Ed25519 is EUF-CMA [21]); certificate size becomes 64q bytes + ⌈n/8⌉.

> *Proof.* Σ enters Theorem A's proof only in the case "honest v signed both π and π′, or A forged v's signature" — a per-signer EUF-CMA property. No step reasons about an aggregate as one object. □

> **PROPOSITION L (verification floor).** With k verification cores, mean service time t̄_v and zero network latency, work conservation gives E[C_(q)] ≥ (q/k)·t̄_v, so E[t_fin] ≥ t_dissem + (q/k)·t̄_v. Per-vote verification is infeasible for every topology once n > (k/0.8)·(T − t_dissem)/t̄_v. An aggregate scheme instead pays t_dissem + t_agg independent of n.

> *Proof.* The q-th completion requires q services; k servers process at most k·t of work by time t, so C_(q) ≥ (Σᵢ₌₁^q t_v,i)/k; take expectations. With t̄_v=0.063 ms, t_dissem=0.046 ms, k=8: n_max ≤ 151. For BLS, t_agg=1.40 ms ⇒ floor ≥ 1.45 ms > T for all n. □

| architecture | t_dissem | Prop. L bound | simulated p99 floor | max one-way | distance |
|---|---|---|---|---|---|
| BLS aggregate, 10 GbE | 0.46 ms | ≥1.86 ms | 1.971 ms | infeasible | — |
| BLS aggregate, 100 GbE | 0.046 ms | ≥1.45 ms | 1.557 ms | infeasible | — |
| Ed25519, 4 cores, 10 GbE | 0.46 ms | ≥0.73 ms | 0.817 ms | 0.111 ms | 22 km |
| Ed25519, 4 cores, 100 GbE | 0.046 ms | ≥0.31 ms | 0.385 ms | 0.313 ms | 62.6 ± 0.2 km |

Last row: mean of 8 independent seeds, 95% CI (range 62.3–63.0 km; p99 at threshold 0.998–1.005 ms, so Monte Carlo error ≤0.5%). Cores: 4 / 8 / 16 lower the zero-latency floor 0.456 / 0.251 / 0.178 ms but leave the distance budget at ≈62 km — at the threshold, propagation binds, not verification.

**Latency factors.** Each factor below was varied with the others at the reference point; derivations, tables and figures are in Appendix D. The two CPU-bound components on the critical path were also measured natively (Appendix D.9): 17-of-21 Ed25519 verification on 4 cores completes at p99 0.353 ms (simulated 0.339 ms), the streaming SHA-384 root finishes 3.57 µs after the last of 4,096 operations (bound 13 hashes), and kernel UDP adds 2.5 µs (busy-poll) to 13.4 µs (blocking) per hop, within the c₀ range of D.6.

| factor | range tested | effect on the p99 ≤ 1 ms budget | App. D |
|---|---|---|---|
| path jitter σ | 0.1 – 1.0 | 66 → 25 km; the dominant network parameter | D.1 |
| post-quantum signatures | ML-DSA-44/65/87, SLH-DSA | ML-DSA-44 to n ≤ 52 (41 KB certs); SLH-DSA infeasible | D.2 |
| Merkle root at batch close | k = 4 – 16 hashing cores | 62.6 → 43.6–58.2 km; streaming (Prop. R) removes the cost | D.3 |
| arrival order | in-order … random | tail 3.0 → 5.3 µs p99 needs 8 hashing cores (Props. R′–R″) | D.4 |
| verification cores | 1 – 16 | k = 1 infeasible, k = 2: 39.7 km, k ≥ 4: ≈62 km | D.5 |
| placement, NIC latency | ring, disk; c₀ ≤ 50 µs | disk 102.6 km (1.64×); −0.24 km per µs of c₀ | D.6 |
| withholding | b = 0 – 6 | b = 2 / 4: p99 1.09 / 1.45 ms at 62.6 km; b ≥ 5 slow path only | D.6 |
| slot period | 0.1 – 32 ms | end-to-end needs Δ_slot ≤ 0.25 ms; in-order commit free | D.7 |
| bandwidth | n ≤ 100 | votes ≤ 0.82 Gbps; batches 18–46 Gbps dominate (Prop. O) | D.7 |
| stake skew | Zipf s = 0 – 1.5 | 63 → 52 km; fast-path Nakamoto coefficient → 1 | D.8 |

> **PROPOSITION R (streaming Merkle root).** Let the leader and each voter hash operations in arrival order with a frontier stack (merge the top two entries while their heights are equal; at batch close fold the stack right to left). (i) The result equals the RFC 6962 root MTH(D) for every m ≥ 1. (ii) Total work is exactly 2m − 1 hashes. (iii) At most ⌊log₂ m⌋ + 1 hashes follow the arrival of the last operation. (iv) Hashing keeps pace with arrivals iff (2m − 1)·t_h/k ≤ Δ_slot, with aligned subtrees of 2^j leaves assigned to k cores.

> *Proof.* (i) After i leaves the stack holds the roots of the perfect subtrees given by the binary expansion of i, largest first. RFC 6962 splits D at the largest power of two k < m; that left subtree is perfect and is the bottom stack entry, and the fold computes H(0x01 ‖ MTH(D[:k]) ‖ MTH(D[k:])) by induction on the remaining entries. (ii) m leaf hashes plus one hash per merge; a binary tree with m leaves has m − 1 internal nodes. (iii) The last leaf costs 1 hash plus t merges, t = trailing ones of m − 1; the fold costs popcount(m) − 1; since popcount(m) = popcount(m − 1) − t + 1, the sum is popcount(m − 1) ≤ ⌊log₂ m⌋ (equality iff m is a power of 2). (iv) Distinct aligned subtrees share no inputs. □

| hashing schedule (m = 4,096, SHA-NI) | critical-path hashing | budget b = 0 | budget b = 4 | hashing cores |
|---|---|---|---|---|
| batch root at close, k = 4 | 0.236 ms | 43.6 km | 30.1 km | 4 |
| batch root at close, k = 8 | 0.118 ms | 53.9 km | 35.3 ± 0.7 km | 8 |
| batch root at close, k = 16 | 0.059 ms | 58.2 km | 38.8 km | 16 |
| **streaming root (Prop. R)** | 13 · t_h = 0.003 ms | **62.5 ± 0.1 km** | **41.6 km** | 4 (8 any order) |
| no hashing (lower bound) | 0 | 62.6 km | 41.6 km | — |

Check: streaming root = RFC 6962 root for all m ≤ 1,024 and 200 random m ≤ 20,000 (0 mismatches, 1,224 cases); hash count = 2m − 1 in every case; the critical-path bound (iii) is attained, never exceeded. Latency: mean ± s.d. over 8 independent seeds, 15,000 slots each. Streaming removes 99.97% of the hashing latency and recovers the hashing-free budget within simulation noise; its price is dedicated hashing cores (Proposition R′).

**Integrated reference design.** All mechanisms at once: 21 validators uniform in a metro disk, c₀ = 5 µs per hop (kernel bypass), 100 GbE, 4 Ed25519 verification cores, SHA-384 streaming roots (5.2 µs tail, 16 hashing cores), b random validators silent, slot wait W ~ U(0, Δ_slot); p99 ≤ 1 ms over 50 layouts, 2 seeds:

| b silent | certificate p99 ≤ 1 ms | end-to-end, Δ_slot = 0.1 ms | end-to-end, Δ_slot = 0.25 ms | batch bandwidth at Δ_slot |
|---|---|---|---|---|
| 0 | 101.4 km | 95.0 km | **80.8 km** | 46 / 18 Gbps |
| 2 | 87.2 km | 81.2 km | 70.6 km | 46 / 18 Gbps |
| 4 (= ⌈n/5⌉ − 1) | 64.3 km | 59.2 km | 50.8 km | 46 / 18 Gbps |

Diameters are metro-disk diameters (seed-to-seed spread ≤ 1.4 km). In-order commit is omitted; it costs ≤ 0.2 km (App. D.7). Each mechanism was validated separately above; this run checks that they compose without interaction effects beyond the additive latency terms.

**Scaling the reference design** (b = 0, Δ_slot = 0.25 ms, end-to-end p99 ≤ 1 ms, 2 seeds):

| n | q = ⌈0.8n⌉ | k = 4 | k = 8 | k = 16 | q·t̄_v/k |
|---|---|---|---|---|---|
| 21 | 17 | **80.8 km** | — | — | 0.27 ms (k=4) |
| 31 | 25 | 76.1 km | — | — | 0.39 ms (k=4) |
| 41 | 33 | 39.9 km | **81.7 km** | — | 0.26 ms (k=8) |
| 64 | 52 | infeasible | 75.1 km | **81.9 km** | 0.20 ms (k=16) |
| 100 | 80 | — | — | **83.9 km** | 0.32 ms (k=16) |

The budget holds at ≈81–84 km whenever the serial verification load q·t̄_v/k stays ≲ 0.3 ms, i.e. k ≈ n/6 verification cores; larger n then helps slightly, as quorums fill from nearer validators. Validator count is a hardware parameter, not a protocol limit, up to n = 100 in simulation (Proposition L caps n at 151·k/8).

> **PROPOSITION S (correlated site failure).** Let validators occupy D sites and let φ be the largest site's stake. After losing that site: φ 4/5); 1/5 ≤ φ 1/3 halts liveness (safety holds by Theorem A). With equal stake the fast path survives any single-site loss iff D ≥ 6.

> *Proof.* Live stake after the loss is 1 − φ; compare with the 4/5 and 2/3 thresholds. Equal stake over D sites gives φ = ⌈n/D⌉/n; for n = 21, φ < 1/5 iff ⌈21/D⌉ ≤ 4 iff D ≥ 6. □

| sites D | largest site | regime after loss | all sites up | largest site down |
|---|---|---|---|---|
| 3 | 7 (φ = 1/3) | slow, all live must vote | 75.8 km | infeasible (p99 1.04–1.11 ms at 1 km) |
| 5 | 5 (φ = 0.24) | slow path | 81.3 km | 28.0 km |
| 6 | 4 (φ = 0.19) | fast, q = all live | 78.3 km | 52.8 km |
| 7 | 3 (φ = 0.14) | fast path | 79.8 km | **62.5 km** |

End-to-end p99 ≤ 1 ms, Δ_slot = 0.25 ms, sites uniform in a metro disk, validators round-robin, 2 seeds (spread ≤ 1.9 km). A deployment that must stay under 1 ms through a data-centre outage needs ≥ 7 sites within ≈62 km; D = 5 survives on the slow path only within ≈28 km.

**Crashed leaders.** The b-silent rows above draw leaders from live validators only. If a crashed validator can be elected, its slot costs a full timeout Δ_to ≈ 1.05 ms (Corollary N1): at b = 4, 50 km, a single proposer per slot gives p99 t_e2e = 2.91 ms and only 80.2% of transactions within 1 ms. The 1 ms tail therefore needs redundant proposers, not more distance margin.

> **PROPOSITION T (K concurrent proposers).** Elect K distinct proposers per slot by VRF; proposer j carries a disjoint 1/K share of the slot's batch, headed h_{t,j} = Hκ(0x02 ∥ t ∥ j ∥ root ∥ h_prev), and each (t, j) runs its own certificate. (i) Safety: Theorems A and A\* hold per (t, j), and Lemma 9′ holds with j in the header. (ii) A transaction sent to all K proposers of a slot is included by the first certified one; all K are crashed with probability C(b, K)/C(n, K). (iii) Dissemination and hashing are unchanged (batch split K ways); vote verification grows K-fold, so k_v = 4K cores keep the per-core load of the K = 1 design.

> *Proof.* (i) Distinct (t, j) give distinct header inputs, so each instance is Theorem A's setting with slot index (t, j). (ii) K proposers are sampled without replacement from n, of which b are crashed. (iii) Batch bytes and leaves per slot total m; each validator verifies K·q votes instead of q. □

| K | P(all K crashed), b = 4 | p99 t_e2e, b = 0 | p99 t_e2e, b = 4 | p99.9, b = 4 | P(t_e2e ≤ 1 ms), b = 4 |
|---|---|---|---|---|---|
| 1 | 19.0% | 0.782 ms | 2.914 ms | 4.851 ms | 80.20% |
| 2 | 2.86% | 0.763 ms | 1.766 ms | 2.008 ms | 96.78% |
| **3** | 0.30% | 0.752 ms | **0.878 ms** | 1.752 ms | 99.61% |
| 4 | 0.017% | 0.746 ms | 0.828 ms | **0.921 ms** | 99.97% |

50 km metro disk, Δ_slot = 0.25 ms, c₀ = 5 µs, k_v = 4K verification cores, 30,000 transactions over 60 layouts; b random validators crashed (silent as voters and as proposers). K = 3 restores p99 ≤ 1 ms with four crashed validators; K = 4 restores p99.9. With k_v = 4 and serialized dissemination instead, K = 3 gives p99 1.37 ms even at b = 0 — the extra votes must be paid for in cores. Scope: (ii) is inclusion finality. The order of conflicting operations across proposers of one slot is fixed only when every lower-ranked (t, j) is certified or timed out, so shared-state operations (the order book) still pay Δ_to when a lower-ranked proposer is crashed (O25).

*Figure 8. Integrated reference design: metro-disk diameter meeting p99 ≤ 1 ms, by silent validators and latency definition; simulated.*

> **PROPOSITION U (fast skip certificates; ordering finality).** For each (t, j) an honest validator casts exactly one vote: for the proposal if it arrives by Δ_skip after slot start, else SKIP. A skip certificate is ⌈0.8n⌉ SKIP votes (fast) or two 2/3 rounds (slow; also the fallback when a split vote reaches neither fast quorum) and binds the root r_⊥ = Hκ(0x03 ∥ t ∥ j). (i) No (t, j) has both a proposal certificate and a skip certificate. (ii) An operation's order is final once every rank ≤ its first certified rank is resolved, which takes t_order ≈ W + max(t_cert, Δ_skip + t_vote) when a lower rank is crashed.

> *Proof.* (i) Treat SKIP as a proposal with root r_⊥. Two fast quorums share ≥ 3/5 of stake; fast and slow share ≥ 7/15 (Lemma 6); two slow share ≥ 1/3 (Lemma 5); each exceeds f < 1/3, so some honest validator voted both, contradicting one vote per (t, j) — or a signature was forged (Theorem A). The 0x03 prefix makes r_⊥ differ from every leaf, node and header digest, so a skip header cannot equal a batch header without an Hκ collision (Lemma 9′). (ii) Execution order is rank-major, so an operation's outcome depends only on ranks up to its first certified one; a crashed rank resolves at Δ_skip plus one vote hop and verification. □

| b crashed | diameter | Δ_skip | spurious skips | inclusion p99 | ordering p99 | ordering p99.9 |
|---|---|---|---|---|---|---|
| 0 | 50 km | 0.35 ms | 0.03% | 0.749 ms | 0.796 ms | 0.878 ms |
| 2 | 30 km | 0.40 ms | 0.00% | 0.689 ms | **0.956 ms** | 0.994 ms |
| 4 | 20 km | 0.35 ms | 0.00% | 0.673 ms | 0.926 ms | 1.439 ms |
| 4 | 30 km | 0.40 ms | 0.07–0.08% | 0.705 ms | **0.977–0.980 ms** | 1.41–1.46 ms |
| 4 | 40 km | 0.45 ms | 0.38% | 0.772 ms | 1.060 ms | 1.625 ms |
| 4 | 50 km | 0.50 ms | 1.20% | 0.890 ms | 1.212 ms | 1.804 ms |
| 4, slow fallback | 40 km | 0.35 ms | 0.00% | 0.819 ms | **0.981 ms** | 1.415 ms |
| 4, slow fallback | 40 km | 0.40 ms | 0.00% | 0.777 ms | **0.992–0.995 ms** | 1.50–1.56 ms |
| 4, slow fallback | 50 km | 0.40 ms | 0.00% | 0.931 ms | 1.081 ms | 1.636 ms |

K = 3, 4 verification cores per rank, Δ_slot = 0.25 ms, 30,000 transactions per row (two seeds where a range is shown); rows without "slow fallback" resolve a split vote by Δ_to. Δ_skip trades crash latency against spurious skips of live proposers: at 50 km, Δ_skip = 0.25 ms skips 85% of live proposals (ordering p99 17 ms), 0.5 ms skips 1.2% but a crashed rank then costs ≈0.5 ms plus a vote round. Shared-state ordering finality at p99 ≤ 1 ms with four crashed validators holds within ≈30 km with a timeout fallback and ≈40 km when split votes fall back to the two-round slow path, against ≈50 km for inclusion finality.

**Robustness of the fast path** (Appendix D.11). At n = 21 the fast path is left by 0% / 0.047% / 1.263% of proposer instances at b = 0 / 2 / 4 crashed validators. Measured host stalls (1.7 per core-ms, p99 214 µs, on this cloud VM) leave the b ≤ 2 envelope intact but pull the b = 4 ordering edge from 40 to 35 km. The cause is zero quorum slack: at b = 4, q equals the live count. Proposition Y quantifies slack σ = n − b − ⌈0.8n⌉ and shows each unit cuts fallback ≈20–30×; n = 31 moves the b = 4 edge to 45 km (50 km borderline) on the same noisy host.

*Figure 9. Left: ordering p99 and spurious-skip rate against the skip deadline (b = 4, 50 km). Right: best ordering p99 against metro diameter; simulated.*

**Full-stack operating envelope** (K = 3 proposers, fast skip certificates with slow fallback, Δ_slot = 0.25 ms, 21 validators in a metro disk, 30,000 transactions per point, two seeds per edge point (ranges); Δ_skip tuned per diameter):

| b crashed | inclusion p99 ≤ 1 ms | ordering p99 ≤ 1 ms | ordering p99 at the edge | Δ_skip at the edge |
|---|---|---|---|---|
| 0 | ≥ 90 km (0.965–0.975 ms) | **70 km** (80 km borderline) | 0.913–0.924 @ 70 km; 1.001–1.003 @ 80 km | 0.55–0.70 ms |
| 2 | ≥ 70 km (0.890–0.891 ms) | **50 km** | 0.969 (both seeds) @ 50; 1.009–1.017 @ 60 km | 0.40 ms |
| 4 (= ⌈n/5⌉ − 1) | 50 km (0.931–0.952 ms) | **40 km** | 0.969–0.981 @ 40; 1.081–1.088 @ 50 km | 0.35–0.40 ms |

The optimal skip deadline grows with diameter: at Δ_skip = 0.4 ms, spurious skips rise from 0.00% at 50 km to 2.1% at 90 km (b = 0) and ordering p99 degrades to 1.41 ms; lengthening Δ_skip to 0.7 ms brings it to 1.001–1.003 ms (borderline) at 80 km. Each crashed validator costs ≈10 km of ordering diameter. This table is the deployable specification: pick the tolerated b, read off the metro diameter.

**Execution and state commitment.** Ordering finality fixes each operation's outcome, since execution is deterministic; two costs remain. Execution, measured with a native price-time-priority order book (C, -O2, one core, one market; 60% limit, 30% cancel, 10% IOC): 43.5 ns/op, a 4,096-op batch in 0.178 ms median (0.323 ms p99), a 1,366-op proposer share in 0.073 ms — well inside a 0.25 ms slot. The state root is the binding cost:

> **PROPOSITION X (state-root budget).** Commit state in a binary Merkle trie of depth D (2^D account slots; leaf prefix 0x06, node prefix 0x07). A root over m uniformly touched keys rehashes E[H] = Σ_{d=0}^{D} 2^d(1 − (1 − 2^−d)^m) ≤ m(D − ⌊log₂ m⌋ + 2) nodes. At load λ ops/s with one root per epoch of E seconds, sustained hashing needs E[H](D, λE)·t_h/E cores; lengthening E amortizes the top ⌊log₂(λE)⌋ levels.

> *Proof.* A level-d node is rehashed iff some touched key lies beneath it: probability 1 − (1 − 2^−d)^m; sum over the 2^d nodes and D + 1 levels. Levels d ≤ ⌊log₂ m⌋ contribute ≤ Σ 2^d < 2m; each deeper level contributes ≤ m, giving m(D − ⌊log₂ m⌋) more. Binding of the state root is Lemma 9 with prefixes 0x06/0x07. □

| load λ (ops/s) | root every 0.25 ms | every 1 ms | every 32 ms | every 256 ms |
|---|---|---|---|---|
| 1 × 10⁶ | 6.8 cores (17.1 h/op) | 6.0 | 4.0 (10.2 h/op) | 2.8 |
| 4 × 10⁶ | 24.1 | 20.9 | **13.0** (8.2 h/op) | 8.2 |
| 16.4 × 10⁶ (4,096 ops / 0.25 ms) | 85.6 (13.1 h/op) | 72.5 | 40.0 | 21.1 |

SHA-384 cores for D = 24 (1.7·10⁷ accounts); h/op = hashes per operation. Expectation checked by direct simulation (≤ 0.3% error, 30 cases); the bound holds in every case. A per-slot state root at the full 4,096-op batch rate would need 86 cores. NIMBUS therefore separates the two finalities: **ordering** (and hence outcome) is final in ≤ 1 ms, while the **state root** for epoch e is computed off the critical path and carried in the first header of epoch e + 1 (E = 32 ms). The same cores also build batch roots (2 hashes/op, Proposition R), so sustained capacity solves 2λt_h + E[H](D, λE)·t_h/E = k_h: with k_h = 16 hashing cores, λ = 4.0 × 10⁶ ops/s at t_h = 0.398 µs (4.4 × 10⁶ at the in-situ 0.364 µs; state root alone would allow 5.2 × 10⁶); 24 cores give 6.4–7.1 × 10⁶. Light-client balance proofs lag by ≤ 2E = 64 ms; transaction-finality proofs (Propositions V, W) do not depend on the state root. Measured natively (C, OpenSSL SHA-384, OpenMP, D = 20): 9.09 hashes/op against 9.11 predicted, 0.364 µs per hash per thread, linear scaling to 4 threads — a 4,096-key root in 3.36 ms against 3.71 ms predicted (Appendix D.10).

> **RESULT (§6.4).** **p99 end-to-end latency ≤ 1 ms is reachable in simulation for a 21-validator metro deployment ≈78 km across at in-place crypto costs (certificate finality alone: ≈99 km; ≈48 km end-to-end tolerating 4 silent voters; crashed leaders need Proposition T) with: per-vote Ed25519 verified on arrival (k ≥ 4, scaled as k ≈ n/6), 100 GbE dissemination, validators within ≈62 km pairwise, or a ≈100 km-diameter metro disk, with streaming Merkle roots (Prop. R; σ ≤ 0.3), n ≤ 100 (≈84 km end-to-end at n = 100, k = 16), no withholding (≈42 km to tolerate b = 4), unconcentrated stake.** BLS aggregates cannot reach it for any n or topology (Proposition L). End-to-end 1 ms additionally needs Δ_slot ≤ 0.25 ms (≤46 km; in-order commit is free). Certificates cost 64q bytes (≈1.1 KB at n=21, ≈3.3 KB at n=64). All figures are simulated with measured cryptographic costs; none is a hardware measurement (O17). Execution costs 43.5 ns/op (measured); the state root is deferred to 32 ms epochs, capping sustained throughput at ≈4 × 10⁶ ops/s on 16 hashing cores, batch and state roots together (Proposition X). Surviving a data-centre outage at 1 ms requires ≥ 7 sites within ≈62 km (Proposition S); surviving crashed leaders requires K = 3 concurrent proposers and 12 verification cores (Proposition T); order-book (shared-state) ordering under four crashed validators holds within ≈40 km via fast skip certificates with slow-path fallback (Proposition U).

⚠ **SCOPE.** An architecture meeting the target in simulation, not a commitment to single-metro topology or to replacing BLS. O18.

### 6.5 Prototype P0: Executable Fast Path

P0 implements the fast path in C (66 lines): each validator is a thread with its own UDP socket; the leader builds the 154-byte 0x02 header, signs its SHA-384 digest with Ed25519 and sends it to all; each validator checks the domain byte and leader signature, signs and broadcasts a vote, verifies every vote it receives, and holds a certificate at q = ⌈0.8n⌉ valid votes on one digest. Leaders rotate per slot; headers chain by h_prev.

| prototype | adds | runs | key result | App. |
|---|---|---|---|---|
| P0 | fast path: UDP, Ed25519, 0x02 headers | 48,000 certs, n = 4–7 | 0 missing, 0 conflicts; CPU-bound on a shared host | E.1 |
| P0 + delay model | lognormal network, pinning | 110,000 certs, n = 3–4 | model median within 0.10–0.13 ms (in-place crypto 1.27×, 3–4 km); pinning cuts p99 2.1–2.3× | E.2 |
| P0-U | skip certificates (0x03) | 30,000 outcomes, n = 5, 1 crashed | all crashed-leader slots skipped; skip = Δ_skip + 0.47–0.51 ms; 0.2–0.3% splits | E.3 |
| P0-TC | timeout certificates (0x08) | 107,500 outcomes, 2,292 TC anchors | 0 unresolved, 0 conflicts; TC anchor at Δ_to + 0.5 ms, commits one slot later | E.4 |

Two protocol rules came out of the prototypes rather than the proofs: a message for an earlier slot is routed to that slot's state and never resets the current one, and a message for a later slot advances the validator's slot state rather than being discarded. Each first build without the rule lost 0.7% and 5% of outcomes respectively. The multi-machine network remains unmeasured (Appendix C).

### 6.6 Reference Engine: Admission, Journal, Matching, Receipts

nimbus-core v0.17 (Rust, twelve crates, no unsafe code) implements what a validator runs after ordering: per slot it expires resting orders past their signed deadline, verifies every signature in ZIP-215 batches on all cores, admits entries in arrival order (keys, deadlines, lifetimes, strict per-account nonces, k-of-m bridge quorum, one-time bridge references, per-slot deposit caps), writes the slot to a hash-chained journal (0x0B) with one fsync that runs concurrently with price-time matching, and signs a checkpoint (0x0C) over the slot, the journal (length, head) and a Merkle root (0x0D/0x0E) of one receipt per state change. A receipt states the exact execution (fills, Σ price × qty, each side's fee) and the account's balance after it; every fill also yields a receipt for the maker, so both sides reconcile every trade offline from ≈ 15 hashes and one signature. Verification of slot s + 1 runs while slot s commits (Proposition Z″). Each slot's journal write is shipped to r replicas while the local fsync runs, and the slot is acknowledged only when a of them return the engine's exact new anchor — inside the slot's commit (blocking) or while later slots commit (windowed; Proposition Z⁗, Corollary Z2). A bridge pays withdrawals and refunds rejected deposits only against such receipts, each once, and only under checkpoints co-signed by a validator quorum (Proposition Z‴).

> **PROPOSITION Z (replay determinism).** Fix genesis G, operator key sk and journal J. Recovery — replaying J from G — reproduces the live engine's state and its entire checkpoint sequence byte for byte, except with probability ≤ β · 2^−128, where β is the number of batch verifications performed.

> *Proof.* (i) Under the signature rule of §2.3, an entry's validity is the conjunction of single ZIP-215 verifications; a batch returns that conjunction unless its random linear combination annihilates a non-zero sum, probability ≤ 2^−128 per batch, so validity is independent of how live processing and replay group signatures. (ii) Admission and matching are deterministic functions of (state, entry, slot), applied in journal order. (iii) Expiry runs at the start of every processed slot; a slot whose only effect is expiry is journaled as a tick, and a slot with neither expiries nor entries changes nothing, so replay applies the same expiries at the same slots. (iv) Ed25519 signing is deterministic [26], so equal checkpoint bodies give equal signatures. □

Consequence: a checkpoint held by any agent binds the operator. A receipt proven under a signed checkpoint cannot be denied without an SHA-384 collision (Lemma 9 applies verbatim to the 0x0D/0x0E tree) or a forgery, and an operator who later truncates or rewrites the journal fails recovery against that checkpoint. Executed: recovery re-derived every stored checkpoint byte for byte in all runs; a journal cut back to its eleventh checkpoint was refused against an agent's later checkpoint; a changed genesis was refused as divergence and a removed bridge key as a replay rejection.

> **COROLLARY Z1 (receipt soundness).** Let an adversary that does not hold the operator key make q SHA-384 evaluations and output (receipt r, index i, path π, checkpoint C) such that C verifies under the operator key and π proves r at i under C's receipt root, while the operator never committed r at i in a checkpoint for that slot. Then Pr[success] ≤ Adv_EUF-CMA(Ed25519) + q²/2^385; at q = 2^80 the hash term is 2^−225.

> *Proof.* Either C was never signed by the operator — a forgery — or C was signed over a tree whose leaf i is not H(0x0D ∥ r). Then the audit path and the committed path hash to one root from different leaf inputs; walking up from the leaf, the first level at which the inputs differ but the outputs agree is an SHA-384 collision (Lemma 9 on the 0x0D/0x0E tree; Lemma 9″ separates these domains from all others). A birthday bound over q evaluations gives q²/2^385. □

> **PROPOSITION Z″ (pipelined screening).** Let the screen for slot s + 1 be evaluated on the admission state A_{s−1} (before slot s commits) instead of A_s. Every submission it refuses is refused on A_s, and admission, evaluated on A_s, then yields exactly the decisions of slot-by-slot processing.

> *Proof.* The screen refuses on four grounds: a key mismatch, an expiry or lifetime violation, a nonce below the account's next nonce, and a bridge reference used within its validity window. Keys never change once registered; expiry and lifetime depend only on the entry and s + 1; next nonces only increase from A_{s−1} to A_s; a reference live in A_{s−1} at slot s + 1 is still stored in A_s (pruning removes only references whose window has closed). So each refusal on A_{s−1} is a refusal on A_s. Entries the stale screen passes are verified and then admitted or refused by admission on A_s, as in slot-by-slot processing. □

> **PROPOSITION Z′ (acknowledgement floor).** Let entries arrive uniformly within slots of length Δ, and let an acknowledgement need one verification t_v, the durable flush t_f and the checkpoint signature t_s. Then the p-quantile of acknowledgement latency is at least pΔ + t_v + t_f + t_s. Hence p99 ≤ 1 ms is impossible at Δ = 1 ms, and at Δ = 0.25 ms requires t_v + t_f + t_s ≤ 0.7525 ms at zero load.

> *Proof.* An entry arriving at offset u ~ U(0, Δ) waits Δ − u for its slot to close; Δ − u exceeds pΔ with probability 1 − p. Processing cannot finish before one verification, the flush (nothing is acknowledged before it is durable) and the signature. □

**Measured** (4-vCPU VM; entries are 90% orders, 5% signed cancels, 3% withdrawals, 2% 2-of-3 bridge deposits; 20,000 entries per slot; final state identical to a sequential single-verification run):

| quantity | value | note |
|---|---|---|
| end to end, fsync per slot | 150–183 × 10³ entries/s pipelined (4 threads); 153–173 × 10³ slot by slot | sequential baseline 17.7–18.3 × 10³/s |
| with 2 replicas, both required | 127–141 × 10³ entries/s pipelined | replicas on the same virtual disk: an upper bound on the cost |
| maker receipts | one per fill (262,303 in the run); cost ≈ 10% of throughput | measured on the v0.7 host |
| with fees (10 bps taker, 5 bps maker) | 167–182 × 10³ entries/s pipelined | no measurable cost |
| native build (target-cpu = native) | 159–170 × 10³ entries/s pipelined vs 150–159 × 10³ default, interleaved | +8% mean; binaries then need this CPU type |
| engine restart | replay from genesis 4485–4623 ms; from a 8.7 MB snapshot 113–115 ms | 600,000 orders; recovery-bench |
| snapshot encode on the engine path | 12.1–12.5 ms per snapshot (1.39 ms/MB); 0 with a follower | seal and write in the background |
| certifier restart | replay from genesis 1615–1726 ms; from a 1.04 MB snapshot 16.6–16.7 ms | 200,000 orders; certify-bench |
| certifier memory | 472 B per slot unbounded; 0.3 B per slot over 400,000 slots with a 1,024-slot window | resident-set growth, certify-mem |
| FOK / post-only | FOK 277–385 ns vs IOC 212–233 ns per order; refused post-only 46–56 ns | match-bench, TIF_SPLIT |
| time shares, 4 threads, slot by slot | verification 61–64%, journal ∥ matching 33–36%, admission 2% | journal branch 29–32% |
| cross-slot pipelining gain | +12% on the v0.7 host; within run-to-run noise here | this host is faster than earlier rounds'; v0.11 code here: same ranges |
| ZIP-215 verification | single 60–65 µs; batched 17.4 µs CPU (4.4 µs wall on 4 cores) | libsodium single: 53 µs (D.9) |
| invalid-signature flood | 1.38–1.45× single-verification CPU | bisection, then singles when dense |
| group commit, 128 orders (26.5 KB) | p50 647 µs, p99 1,827 µs, p99.9 3,512 µs | this VM's virtual disk |
| journal record (order) | 207 B | variable length; was 240 B |
| receipt proof | 15 hashes; build ≈ 1 µs; agent check 75–117 µs | dominated by the signature |

**Acknowledgement latency** (Monte Carlo, analysis/engine_mc.py, driven by the measured single-core batch costs for 1–4,096 signatures and the measured group-commit samples; per-entry admission 0.3 µs, matching and receipts 2.2 µs, signature 28 µs; slots served in order). Largest arrival rate, in entries per ms, with a stable queue and p99 ≤ 1 ms at Δ_slot = 0.25 ms; minimum batch 16 is the throughput setting, 1 the latency setting:

| durable flush | min batch | k = 4 | k = 16 | k = 64 |
|---|---|---|---|---|
| VM group commit (measured) | 16 | 0 | 0 | 0 |
| VM group commit (measured) | 1 | 0 | 0 | 0 |
| device flush 50 µs (assumed) | 16 | 14 | 13 | 14 |
| device flush 50 µs (assumed) | 1 | 37 | 86 | 130 |
| device flush 20 µs (assumed) | 16 | 17 | 17 | 17 |
| device flush 20 µs (assumed) | 1 | 46 | 89 | 131 |
| device flush 50 µs (assumed), pipelined | 1 | 71 | 218 | 350 |
| device flush 50 µs (assumed), pipelined, Δ_slot = 0.125 ms | 1 | 42 | 96 | 119 |
| device flush 20 µs (assumed), pipelined | 1 | 70 | 222 | 350 |
| device flush 20 µs (assumed), pipelined, Δ_slot = 0.125 ms | 1 | 41 | 97 | 121 |

Three conclusions. (1) This VM's disk cannot acknowledge within 1 ms at any load; the engine needs a durable flush ≤ 50 µs (power-loss-protected NVMe class; Appendix C, T13). (2) Batching trades latency for throughput: a lone signature costs 70 µs, a 16-signature batch 33 µs each, a 4,096-signature batch 18 µs each. Large slots should batch; sub-millisecond slots should spread single signatures over all cores, which lifts capacity from 13–17 to 37–46 / 86–89 / 130–131 entries per ms at k = 4 / 16 / 64 (T14), and pipelining verification of slot s + 1 with the commit of slot s lifts it again to 70–71 / 218–222 / 350. The setting changes no result (executed: identical checkpoints over 25 slots, and pipelined = slot by slot over 40). Halving the slot to 0.125 ms lowers capacity (41–42 / 96–97 / 119–121): smaller batches cost more per signature. (3) At Δ_slot = 1 ms no configuration meets p99 ≤ 1 ms (Proposition Z′); with the latency setting and a 20 µs flush it meets p99 ≤ 2 ms up to 54 / 146 / 244 entries per ms. Verification costs are this host's; faster cores scale capacity proportionally. Pipelining (verification of s + 1 on the cores while s waits for its flush) is modelled as a two-stage tandem queue with the stages on separate resources.

**Dispatch, executed.** The model starts the k verification chunks the moment a slot closes. Measured on this VM (sig-bench; 8 signatures, the traffic of one slot at 16–32 entries/ms, after an idle gap of 0–1 ms; 400 trials each), p50 / p99 in µs:

| method | p50 (µs) | p99 (µs) | model |
|---|---|---|---|
| one batch, one core | 259–349 | 406–478 | 280 (8-signature batch) |
| rayon, 4 threads, min batch 1 | 434–489 | 4404–4433 | 99 (2-signature batch per core) |
| spin pool, 3 workers + caller | 155–173 | 619–1835 | 99 |

Spreading a small slot over a sleeping thread pool is slower than not spreading it: waking the workers costs ≈365 µs, more than Δ_slot. SpinPool (nimbus-sig) keeps its workers spinning on a generation counter and costs ≈64 µs over the model; its results equal verify_all (tested). Adding the measured overhead to the model (analysis/engine_dispatch_mc.py; pipelined, latency batching, Δ_slot = 0.25 ms, 50 µs flush) gives p99 ≤ 1 ms capacities of 43 / 121 / 279 entries/ms at k = 4 / 16 / 64 with the spin pool and 0 / 0 / 0 with the thread pool, against 68 / 220 / 351 for zero dispatch cost. The capacities quoted above are therefore upper bounds, reached only with reserved, never-sleeping verification cores; the spin pool's p99 on this shared VM is host-stall-bound, which T12 and T16 test.

**Fees.** A market's schedule (maker rate m, taker rate t, in basis points, at most 10%, B = max(m, t), a collector account) is fixed while any order rests. A fill of notional n charges the taker ⌈n·t/10⁴⌉ and the maker ⌈n·m/10⁴⌉, both stated in the fill and in the maker's receipt: the buyer pays n + fee, the seller receives n − fee, the collector both fees. A bid for r lots at p locks L(p, r) = p·r + ⌈p·r·B/10⁴⌉ + r (p·r without fees). A market may instead pay makers a rebate at rate ρ ≤ t, only with m = 0: the maker of each fill receives ⌊n·ρ/10⁴⌋, out of the taker's fee, and the collector keeps ⌈n·t/10⁴⌉ − ⌊n·ρ/10⁴⌋; fill and maker receipt state it.

> **PROPOSITION Z5 (fee accounting).** For 1 ≤ q ≤ r, fill price p′ ≤ p and rate b ≤ B: (i) L(p, r) − L(p, r − q) ≥ p′q + ⌈p′q·b/10⁴⌉, so releasing the lock of the filled lots always pays the fill and its fee, and matching never overdraws; (ii) every fill changes Σ_accounts(quote) by zero, so supply is conserved exactly; (iii) for any split n = Σ n_i, Σ⌈n_i·b/10⁴⌉ ≥ ⌈n·b/10⁴⌉: no order lowers its fee by trading in pieces; (iv) each charged fee exceeds the exact n·b/10⁴ by less than one quote unit, a relative error below 10⁴/(n·b); (v) with a rebate ρ ≤ t and m = 0, the collector's take per fill is ≥ 0 and exceeds the exact spread n·(t − ρ)/10⁴ by less than 2 units, (i)–(ii) still hold, and Σ⌊n_i·ρ/10⁴⌋ ≤ ⌊n·ρ/10⁴⌋: no maker earns more rebate by being filled in pieces.

> *Proof.* (i) ⌈x⌉ − ⌈y⌉ > x − y − 1, so the difference D exceeds X − 1 with X = pq + pqB/10⁴ + q; D is an integer, hence D ≥ ⌊X⌋ = pq + q + ⌊pqB/10⁴⌋ ≥ pq + ⌈pqB/10⁴⌉ + q − 1 ≥ pq + ⌈pqB/10⁴⌉ ≥ p′q + ⌈p′q·b/10⁴⌉, using q ≥ 1, p′ ≤ p and b ≤ B. (ii) The buyer loses n + f_b, the seller gains n − f_s, the collector gains f_b + f_s. (iii) ⌈·⌉ is superadditive: Σ⌈x_i⌉ ≥ ⌈Σ x_i⌉. (iv) 0 ≤ ⌈x⌉ − x < 1 and x = n·b/10⁴. Floor rounding would fail (iii) and let dust trades pay nothing. (v) ⌈n·t/10⁴⌉ ≥ n·t/10⁴ ≥ n·ρ/10⁴ ≥ ⌊n·ρ/10⁴⌋, and the excess is (⌈x⌉ − x) + (y − ⌊y⌋) < 2; with m = 0 the maker pays no fee, so the lock of (i) is unchanged and the rebate moves quote from the collector to the maker; ⌊·⌋ is subadditive. Rebates round down for the same reason fees round up. □

Executed: the engine against a naive reference that keeps only per-account totals and re-derives every lock from the book after each operation (so a lock shortfall would underflow), under six schedules (two with rebates: ρ = 10 of t = 25 bps, ρ = t = 30) up to the 10% maximum and at magnitudes up to 2⁶⁴ ticks and lots; six hand-worked fills (two with rebates); the fee formula, written to avoid overflow, equal to exact ⌈n·b/10⁴⌉ on all u128; (i) on 896,700 grid and random cases with 0 failures; (iii) on 200,000 random splits with 0 failures — floor rounding is cheaper by splitting in 192,481 of them; over 400 pipeline slots the collector's balance in every market equals the sum of the fees stated in the receipts. Rounding (analysis/fee_mc.py, 200,000 fills per row): the mean overcharge is 0.5 quote units per side per fill at every size; the largest relative overcharge is 100% / 20% / 2% / 0.2% at 5 bps and 33% / 4% / 0.4% / 0.04% at 25 bps for notionals of 10³ / 10⁴ / 10⁵ / 10⁶ units, so quote units should make n·b ≥ 10⁶ for fees exact to 1%. The reserve ⌈p·r·B/10⁴⌉ + r ties up ≈ B/10⁴ + 1/p of a bid's notional (0.15% at p = 1,000 ticks, B = 5) and returns on fill or cancel. Fees cost no measurable throughput. Rebates (analysis/rebate_mc.py, v0.14): the engine's overflow-free floor equals ⌊n·ρ/10⁴⌋ on 1,000,000 random u128 cases; the collector's take is ≥ 0 in 5,904,478 grid and random cases (largest excess over the exact spread 1.98 units); splitting never raised a rebate in 500,000 random splits and forfeits ≈ 5 units per split of 2–20 pieces; quote is conserved over 309,666 random fills.

**Order types.** An order (p, q) carries a time in force: GTC rests its remainder, IOC releases it, FOK fills q in full or is refused, post-only rests without taking or is refused. For an order of account a let A = Σ{q_j : resting order j on the opposite side at a price crossing p, owner(j) ≠ a}.

> **PROPOSITION Z7 (fill-or-kill and post-only).** (i) Matching fills exactly min(q, A), at prices no worse than p. (ii) FOK is admitted iff A ≥ q and then fills q exactly; otherwise it is refused and the market's state hash is unchanged. (iii) Post-only is admitted iff the best opposite price does not cross p (own orders included); it then takes no fill in its own operation, so every fill of it is as maker: it pays the maker rate and receives the rebate (Proposition Z5 (v)); otherwise it is refused with the state unchanged. (iv) The FOK test visits at most the orders matching visits, so it at most doubles the order's matching cost.

> *Proof.* (i) Matching visits crossing levels best-first and each level in time order; at a head of account a it removes the order (self-trade prevention, no quantity filled); at any other head it fills min(remaining, q_j). It stops when remaining = 0 or no crossing level is left, so the filled quantity is min(q, A). (ii) The test walks the same levels in the same order, summing non-own quantities, and stops at q: it computes [A ≥ q]. A refusal returns before the lock is taken or any order is touched. (iii) If the best opposite price does not cross p no level crosses, so the loop of (i) does not run; the order rests and later fills only as the resting side. (iv) The test stops at the order at which matching would complete. □

Executed: the differential reference engine now draws GTC, IOC, FOK and post-only orders (4 : 2 : 1 : 1) under all six fee schedules at normal and extreme magnitudes, with FOK implemented independently as a sum over the book; five hand-worked cases (FOK = IOC when fillable; FOK short by one lot refused with the state hash unchanged; own orders not counted; post-only resting and earning ⌊19,800·10/10⁴⌋ = 19 as maker; post-only refused against another's and its own order); pipeline runs with all four types, every receipt checked against the sequential reference. Cost (match-bench, 2·10⁶ operations, every IOC of the stream replaced, 3 runs): IOC 212–233 ns, FOK 277–385 ns per order (all fillable in this stream), a refused post-only 46–56 ns.

**Settlement.** Funds leave only through the bridge, which pays a withdrawal or refunds an engine-rejected deposit against a receipt proof (Corollary Z1 bounds forgery), records the receipt leaf durably before releasing the instruction (each receipt settles once, across restarts), and refuses a second checkpoint for a slot it has settled against. The operator's signature alone cannot stop a fabricated checkpoint for a slot the bridge has not seen, so a certified bridge also requires q distinct validator signatures on the same 0x0C digest, with 2n < 3q ≤ 3n checked when the validator set is built.

> **PROPOSITION Z‴ (certified settlement).** Let n validators certify checkpoints with quorum q, 2n < 3q ≤ 3n, of which at most f < n/3 are faulty; an honest validator co-signs, per slot, only the checkpoint it re-derives by replaying the replicated journal (Proposition Z). Against an adversary holding the operator key and the faulty validators' keys and making Q SHA-384 evaluations: (i) a checkpoint no honest validator re-derived is certified with probability ≤ (n − f)·Adv_EUF-CMA + Q²/2^385 + 2^−128; (ii) except with the same probability, each slot has at most one certified checkpoint; (iii) if f ≥ n/3, two certified checkpoints for one slot name ≥ 2q − n validators that signed both.

> *Proof.* (i) A certificate is ≥ q signatures under distinct indices on d = H(0x0C ∥ body(C)), verified in one ZIP-215 batch, which accepts only if every signature verifies singly, except with probability 2^−128 (§2.3). Since q > 2n/3 and f < n/3, q − f > 0: some signature is under an honest key. Either that validator signed d — then it signed H(0x0C ∥ body(C′)) for the checkpoint C′ ≠ C it re-derived, an SHA-384 collision (Lemma 9″ fixes the body layout) — or the signature is a forgery against one of n − f honest keys. (ii) Two quorums share ≥ 2q − n > n/3 > f indices, so some honest validator signed both, and it signs one checkpoint per slot; the alternatives are the events of (i). (iii) The shared indices signed both digests; each is a slashable double signature. □

Executed (n = 7, q = 5): missing, 4-of-5, repeated-signer, unknown-index and other-slot certificates refused; an operator-fabricated, validly signed checkpoint for an unseen slot — paid by an uncertified bridge — refused with two faulty co-signers and when padded with honest signatures of another checkpoint; q = 4 (3q ≤ 2n) refused at setup.

**Certifiers.** Proposition Z‴ assumes what a validator's Certifier (nimbus-bridge) does: it is a journal replica, so it receives the journal over the authenticated transport (Corollary Z3) and makes each batch durable; it re-executes every slot with Replayer — the recovery state machine without the operator's key — and keeps the checkpoint body it derives; certify(C) checks the operator's signature, requires the body of C to equal its own, records (slot, digest) durably and only then returns its signature over the 0x0C digest. It refuses a second, different checkpoint for a slot it has signed, including after a restart.

> **COROLLARY Z6 (certifier soundness).** A certifier co-signs a checkpoint C for slot s only if C is operator-signed and its body equals the body that deterministic re-execution of the certifier's own durable journal yields for s (Proposition Z); it releases at most one digest per slot over its lifetime, crashes included. Certifiers that hold the same journal therefore never refuse each other's checkpoints, a checkpoint that misstates any receipt, balance or journal anchor gets no honest co-signature, and the hypotheses of Proposition Z‴ hold for every honest validator running it. With a retention window of W slots (v0.15) the same holds while memory stays ≤ W·b + O(1) and the signing log ≤ 56·(2W + 65) bytes, b = 472 B measured; slots below the floor F = s_max − W + 1 are refused.

> *Proof.* Signing requires equality of 0x0C digests, i.e. of (slot, journal length, journal head, receipts root, receipt count) except with an SHA-384 collision (Lemma 9″); the journal head binds the certifier's records (Lemma 9‴) and the receipts root every receipt (Lemma 9, Corollary Z1), and Replayer is the replay function of Proposition Z. The (slot, digest) record is made durable before the signature exists and is reloaded on start, and a second digest for a recorded slot is refused, so no execution — interrupted or not — releases two. Retention keeps the invariant that every record removed from disk has slot < F_d, the floor stored durably before the removal; F never decreases (it is the maximum of F_d and s_max − W + 1, also when the journal is replaced by a shorter one) and certify refuses s < F, so a pruned slot is never signed again and a retained slot keeps its record. □

Executed: Replayer reproduces every engine checkpoint over 60 mixed slots (orders, cancels, withdrawals, fees, empty slots); four certifiers attached to a live engine as replicas re-derive every slot, three of them certify a withdrawal's checkpoint and the certified bridge pays it; an operator-fabricated, validly signed checkpoint for the same slot gets no co-signature, nor do a future slot or an unsigned checkpoint; a journal whose chain is intact but which carries one forged order signature is refused at open; after a restart a certifier re-derives the same bodies and returns the identical signature, and with its journal replaced by an equivocating history it refuses that history's checkpoint for the slot it already signed. Measured (certify-bench, 100 slots × 2,000 orders, 3 runs): re-execution at 116–124 × 10³ entries/s, 0.92–1.08× the engine on the same cores, and certify 236–272 µs at p50 (903–1112 at p99), dominated by the durable record. Certification is on the settlement path, not the trading path. With quorum q = ⌊2n/3⌋ + 1 and each certifier unavailable independently with probability u, a checkpoint cannot be certified with probability Σ_{k < q} C(n, k)(1 − u)^k u^{n−k} (analysis/certify_mc.py; Monte Carlo agrees): 3.4·10^-5 for n = 7 and 2.8·10^-11 for n = 22 at u = 1%; 3.8·10^-3 and 6.6·10^-6 at u = 5%.

**Retention.** Without a window a certifier's memory grows by 472 B per slot (certify-mem, measured: resident-set growth over 150,000 slots, three runs) — 1.9 MB/s or ≈ 160 GB per day at Δ_slot = 0.25 ms. A certificate verifies without the certifiers, so W must cover only the time to collect q co-signatures after release. Modelled (analysis/retention_mc.py: replica flush resampled from this host's measured group commits with a Hill-fitted Pareto tail, α = 3.2, certify lognormal from certify-bench; the binomial order-statistic formula checked by direct simulation), the window that misses with probability ≤ 10⁻⁹ at Δ_slot = 0.25 ms is W = 51 / 20 / 9 slots for (n, q) = (4, 3) / (7, 5) / (21, 15) co-located and 91 / 60 / 49 at 1,000 km. Host stalls on a shared VM exceed these tails (tcp-bench p99 up to 33 ms), so W = 4,096 slots (1.0 s, ≈ 1.8 MB) is the recommended setting; the retaining certifier's (W = 1,024) resident set went from 3.96 to 4.06 MB over 400,000 slots (0.3 B per slot); one of three shorter runs grew 359 B per slot, not reproduced and not explained.

**Restart.** A certifier that replays its journal from genesis on start needs time proportional to the whole history and, re-executing at about the engine's rate, may never catch up under load. It therefore writes a snapshot every K slots: the canonical encoding of the complete replay state σ — every market (balances, both books in price-time order, next order id, supply, fees), admission (keys, nonces, live bridge references, deposit-cap state), pending expiries — with the journal anchor (n, h, byte length) it was taken at and the retained checkpoint bodies, sealed by H(0x12 ∥ body). On start it decodes the newest snapshot, opens the journal at the anchor without reading the prefix (only the stored link before byte b is compared with h), and re-executes the suffix; any mismatch falls back to replay from genesis.

> **PROPOSITION Z8 (snapshot resumption).** Let R be the replay function (Proposition Z), σ_k the state after the first k slots, enc the snapshot encoding and dec its decoder. (i) dec(enc(σ_k)) = σ_k, and dec accepts only canonical encodings: dec(x) = σ implies enc(σ) = x. (ii) For every k ≤ m, applying slots k+1..m to dec(enc(σ_k)) yields the same checkpoints as R from genesis. (iii) A certifier resumed from its snapshot satisfies Corollary Z6 and the retention invariant. (iv) Restart costs O(|σ| + suffix) instead of O(history); with a snapshot every K slots and engine load λ < r_c, the certifier is level again after t_restore + λ(A + D)/(r_c − λ), A ≤ K·Δ_slot the snapshot's age and D the downtime.

> *Proof.* (i) enc lists every field of σ — including the next order id and supply, which the state hash omits — in a fixed order with sorted keys; dec rebuilds each book by appending orders in the encoded order, which restores price-time priority, and refuses unsorted keys, an unissued or repeated order id, a lock that differs from the book, a crossed book or supply ≠ Σ balances. (ii) follows from (i): R is a function of (σ_k, slots k+1..m). (iii) The snapshot is the certifier's own derivation, sealed against corruption; the journal suffix is verified link by link from the anchor, so the records re-executed are those the anchor commits to (Lemma 9‴); signing records and the floor are loaded as before. (iv) The prefix is neither read nor re-executed; the backlog grows at λ and drains at r_c. □

Executed: a restored market behaves identically on every later operation (property test, 20,000 cases, all four order types and three fee schedules); damaged encodings are refused or canonical; a restored admission decides every later entry identically (deposit cap, references, nonces); over 40 mixed pipeline slots, a snapshot at every one of the 41 cut points resumes to the uninterrupted checkpoints and re-encodes to the same bytes; a certifier resumes at its newest snapshot, derives what full replay derives, returns the identical signature and keeps replicating; a damaged snapshot or a substituted journal falls back to full replay and still refuses the equivocating checkpoint. Measured (certify-bench, 200,000 orders, 1,024 accounts, 3 runs): replay from genesis 1615–1726 ms; a 1.04 MB snapshot written in 5.4–6.9 ms (fsync included), resume from it 16.6–16.7 ms. Catch-up (analysis/snapshot_mc.py; measured r_e, r_c, restore and write rates; downtime lognormal, median 5 s, p99 60 s, assumed): with K = 4,096 slots (1 s) the p50 / p99 time to be level is 6 s / 63 s at ρ = 0.5 and 70 s / 0.5 h at ρ = 0.9; replay from genesis after one day of history takes 24.5 h and 10.0 d. Since v0.17 sealing and writing run on a background thread; the replication path pays only the encoding.

> **COROLLARY Z8′ (the snapshot seal binds the state).** For replay states σ ≠ σ′, H(0x12 ∥ enc(σ)) = H(0x12 ∥ enc(σ′)) yields an SHA-384 collision. Hence a sealed snapshot that verifies decodes to the state that was sealed except with probability ≤ Adv_coll(SHA-384); corruption by a non-adversarial process is undetected with probability 2^−384 per snapshot.

> *Proof.* enc is injective: dec(enc(σ)) = σ (Proposition Z8 (i)). Equal seals with σ ≠ σ′ give distinct inputs 0x12 ∥ enc(σ) ≠ 0x12 ∥ enc(σ′) with equal SHA-384 outputs. 0x12 is a registry domain (Lemma 9″), so no input of another domain is a snapshot input. □

**Engine restart.** The engine itself recovered by replay from genesis. It now resumes the same way: from a snapshot of its own state it reads only the checkpoints after the snapshot (entries are fixed-size and in slot order: binary search) and the journal suffix, re-derives and checks those, and keeps the earlier checkpoint entries as stored. An external checkpoint at or before the snapshot must equal a stored entry; any mismatch, a damaged snapshot or a journal that does not continue the snapshot's anchor falls back to replay from genesis, which reports exactly what it reported without snapshots. Snapshots come from the engine (Pipeline::set_snapshot_every: encoded at the end of a slot, sealed and written on a background thread) or from a SnapshotFollower: a thread or process that reads the engine's journal read-only, applies a slot only once the engine's checkpoint for it is on disk (after the slot's fsync), requires its re-derived checkpoint to equal the engine's, and writes the snapshot. Expiry entries of orders that already left the book are dropped from both the snapshot and the engine's index (they produce no outcome; order ids are never reused).

> **PROPOSITION Z9 (snapshot stall).** Let an engine at load ρ serve slots of length Δ and pause for S = e·M every K slots (e the encode time per MB, M the snapshot size). In the fluid limit a pause delays n(S) = max(0, S − (L − ρΔ)) / ((1 − ρ)Δ) slots beyond the latency budget L, so the fraction of slots over L is n(S)/K, and p99 ≤ L requires K ≥ 100·n(S). A follower makes S = 0 on the engine's path at the cost of re-executing the journal without signature checks on other cores.

> *Proof.* After the pause the backlog is S and decreases at rate 1 − ρ per unit time (work ρΔ arrives per Δ), so it lasts S/(1 − ρ) and covers S/((1 − ρ)Δ) slot arrivals; a slot exceeds L while the backlog exceeds L − ρΔ, i.e. for the first (S − (L − ρΔ))/((1 − ρ)Δ) of them. □

Executed: the engine resumes at its newest snapshot with the state and checkpoints of full replay and then produces identical results for 15 more slots; a damaged snapshot, an agent's checkpoint the engine no longer stores, and records cut after the snapshot fall back or are reported as without snapshots; a torn checkpoint entry is re-derived on a resumed open with every earlier entry kept; a follower thread snapshots a live engine and the engine resumes from it with no record to re-execute; a follower stops at a checkpoint that differs from its derivation. Measured (recovery-bench: 300 slots × 2,000 signed orders, 16 markets, 4,096 accounts, 78,589 orders resting, 3 runs per mode): restart from genesis 4485–4623 ms, from the 8.7 MB snapshot 113–115 ms; slot p50 14.8–16.1 ms without snapshots, 14.8–15.9 ms with engine snapshots every 50 slots (the snapshot slot pays 12.1–12.5 ms of encoding, 1.39 ms per MB), 19.4–20.1 ms with a follower on the same four cores, which kept up within one slot. Stall (analysis/snapshot_stall_mc.py: Lindley recursion, measured e, lognormal service with CV 0.3 assumed; Δ = 0.25 ms, L = 1 ms; K tried in powers of two): for the measured 8.7 MB state at ρ = 0.5, p99 ≤ 1 ms first holds at K = 16,384 (4 s; fluid bound 8,987), for 100 MB at 33 s; p99.9 at 33 s and 262 s. For the 1 ms target the follower on its own cores is the configuration.

**Replication.** A single disk makes every acknowledged trade depend on one machine. Journal::replicate verifies shipped records against the replica's own chain before writing, fsyncs, and returns the replica's anchor; the engine acknowledges slot s when its own fsync and a of r replicas have returned its exact new anchor, and otherwise stops without acknowledging.

> **PROPOSITION Z⁗ (replicated acknowledgement).** Let slot s be acknowledged under replication (r, a), with replica round trips R₁ … R_r, R_(a) the a-th smallest, flush t_f and slot length Δ. (i) Durability: 1 + a journals hold records 0 … len(s) byte-identical to the engine's, except with probability ≤ Q²/2^385; any of them replays to every checkpoint through s (Proposition Z), so s survives the loss of any a of these machines. (ii) Blocking replication: slot s + 1 commits only after R_(a) + t_f for slot s, so the queue is stable only if E[S] < Δ, S ≥ R_(a) + t_f the commit-stage service time. With R ≥ 2(c₀ + d/v) at distance d, fibre speed v and stack cost c₀: d < v(Δ − t_f)/2 − v·c₀. (iii) Windowed replication (receipts of s released when its acknowledgements arrive while s + 1, s + 2, … commit): the p-quantile of acknowledgement latency is at least pΔ + t_v + t_f + t_s + R_(a),p, where R_(a),p is the p-quantile of R_(a).

> *Proof.* (i) The engine counts an acknowledgement only if the replica's anchor (length, head) equals its own. The replica wrote only records it verified as continuing an anchor equal to the engine's previous one, so by induction its journal and the engine's have equal length and equal heads; if they differ, Lemma 9‴ extracts an SHA-384 collision. Replay is a function of the journal (Proposition Z). (ii) Lindley's recursion C_s = max(V_s, C_{s−1}) + S_s with arrivals every Δ has C_s − sΔ → ∞ when E[S] ≥ Δ (Loynes). (iii) As Proposition Z′, with the acknowledgement also waiting for R_(a) + t_f after the journal write is issued. □

Numerically, v = 200 km/ms, c₀ = 10 µs, t_f = 50 µs, Δ = 0.25 ms: (ii) gives d < 18 km before jitter; (iii) at p = 0.99 with t_v = 70 µs, t_s = 28 µs gives R_(a),0.99 ≤ 0.60 ms, i.e. d ≤ 58 km without jitter and ≈ 28 km under the lognormal jitter σ = 0.3 of §6.4 (p99/median = 2.0). Monte Carlo (analysis/replication_mc.py; engine costs as above, pipelined, latency batching; 207 B records over 25 Gbps; all network parameters assumed): largest arrival rate, entries per ms, with p99 ≤ 1 ms, replicas at distance d:

| design, replicas (r, a) | k | 0.1 km | 5 km | 10 km | 20 km | 40 km |
|---|---|---|---|---|---|---|
| none | 16 | 220 | 220 | 218 | 221 | 219 |
| blocking, (2, 1) | 16 | 220 | 219 | 220 | 5 | 0 |
| blocking, (2, 1) | 64 | 350 | 350 | 344 | 5 | 0 |
| blocking, (2, 2) | 16 | 219 | 213 | 169 | 1 | 0 |
| blocking, (2, 2) | 64 | 350 | 349 | 184 | 1 | 0 |
| blocking, (4, 3) | 16 | 222 | 220 | 215 | 2 | 0 |
| blocking, (4, 3) | 64 | 349 | 348 | 317 | 2 | 0 |
| windowed, (2, 1) | 16 | 216 | 222 | 215 | 216 | 63 |
| windowed, (2, 1) | 64 | 351 | 349 | 350 | 348 | 186 |
| windowed, (2, 2) | 16 | 215 | 217 | 216 | 196 | 0 |
| windowed, (2, 2) | 64 | 349 | 350 | 350 | 344 | 0 |
| windowed, (4, 3) | 16 | 215 | 220 | 219 | 207 | 2 |
| windowed, (4, 3) | 64 | 348 | 350 | 350 | 348 | 0 |

Largest replica distance meeting p99 ≤ 1 ms at 50 and 150 entries per ms (k = 16): blocking (2, 1) 16 and 15 km / (2, 2) 11 and 10 km / (4, 3) 12 and 12 km; windowed (2, 1) 42 and 35 km / (2, 2) 28 and 23 km / (4, 3) 36 and 30 km. Replication costs no capacity inside a data centre; the blocking design stops working once the round trip approaches Δ_slot, which is Proposition Z⁗(ii); windowing removes that cliff and leaves the latency floor (iii). Waiting for the fastest a of r (r > a) trims the jitter tail. Engine replicas for 1 ms acknowledgement belong in one metro zone, closer than the validator set itself (§6.4).

> **COROLLARY Z2 (windowed release).** Under windowed replication with quorum a and window depth w, the engine releases slot results in slot order; each released slot s is held, byte-identical, by the engine's journal and by at least a replicas (except with probability ≤ Q²/2^385); at most w committed slots are unreleased; and the released sequence equals the sequence blocking replication returns for the same input.

> *Proof.* Replica i receives batches in commit order and applies them in that order; the engine queues, per replica, the anchor it expects after each batch and counts an acknowledgement only if it equals that anchor, so acked_i is the length of a prefix replica i holds identically (Proposition Z⁗(i)). The head of the pending queue is released only when #{i : acked_i ≥ len(s)} ≥ a, and only the head is ever released, so releases follow slot order. Submission blocks while more than w slots are pending. Replication runs after admission, matching and checkpoint signing and feeds nothing back into them, so the committed results are those of blocking mode; windowing changes only when they are released. □

**Replication, executed** (repl-bench: 2,000 slots of 8 signed orders every Δ_slot = 0.5 ms — the slot this VM sustains — latency batching on a spin pool, two replicas both required behind an emulated pipelined link that returns each acknowledgement one round trip after shipping; journals on tmpfs; median of 3 runs). Release time after slot close:

| round trip (achieved) | blocking p50 | blocking p99 | stable | windowed p50 | windowed p99 | stable |
|---|---|---|---|---|---|---|
| 0 µs (17) | 0.38 ms | 4.8 ms | 3/3 | 0.44 ms | 34.8 ms | 3/3 |
| 100 µs (201) | 113.49 ms | 249.4 ms | 0/3 | 0.91 ms | 12.4 ms | 2/3 |
| 200 µs (304) | 266.63 ms | 516.2 ms | 0/3 | 0.91 ms | 7.7 ms | 3/3 |
| 300 µs (431) | 443.72 ms | 885.9 ms | 0/3 | 4.14 ms | 30.2 ms | 2/3 |
| 500 µs (628) | 599.62 ms | 1228.1 ms | 0/3 | 1.35 ms | 8.2 ms | 3/3 |
| 800 µs (925) | 925.68 ms | 1810.7 ms | 0/3 | 1.43 ms | 9.0 ms | 3/3 |

Blocking replication falls behind once the achieved round trip reaches ≈188 µs: per-slot engine work (≈0.4 ms here) plus the round trip exceeds Δ_slot, as Proposition Z⁗(ii) predicts. Windowed replication kept up in at least 2 of 3 runs at every round trip up to ≈927 µs, with median release ≈ engine time + round trip; its tails (p99 several ms) and the occasional unstable run come from this 4-vCPU VM, where the spinning worker, the engine and both replica threads share four cores. The emulation validates the queueing structure, not the network.

**Authenticated transport.** nimbus-replica carries the journal over TCP with several batches in flight. Every message is authenticated over a new registry domain, 0x11 (role ∥ replica ∥ from ∥ to, Lemma 9″): the replica's hello and acknowledgements by the replica, shipments by the operator — with Ed25519 signatures (transferable) or HMAC-SHA384 under a per-link secret. A replica writes nothing unless the shipment is authenticated, continues its journal and ends exactly at the authenticated anchor; the engine counts an acknowledgement only if it is authenticated, continues the previous one and equals the anchor it expects, and drops a replica whose oldest batch exceeds a timeout or whose in-flight count reaches a cap.

> **COROLLARY Z3 (authenticated replication).** Let a network adversary control every link but hold no link secret and no replica or operator signing key, and make Q SHA-384 evaluations. The engine counts replica i as holding a journal prefix that replica i does not hold durably with probability ≤ Adv_auth + Q²/2^385 per acknowledgement, where Adv_auth is Adv_EUF-CMA(Ed25519) with signatures and Adv_PRF(HMAC-SHA384) with MACs; a replica stores a record the operator did not ship with the same bound. Hence Corollary Z2's durability holds over an adversarial network, and the adversary's only lever is delay, which the timeout converts into a dropped replica.

> *Proof.* An acknowledgement is counted only if its tag verifies on H(0x11 ∥ 1 ∥ i ∥ from ∥ to) for replica i's key or link secret; producing one that replica i did not produce is a forgery (or, for HMAC, a PRF distinguisher). Replica i produces it only after replicate_to has made the records from `from` to `to` durable. A tag on another role, replica index or anchor pair is a tag on a different registry input (Lemma 9″); a tag on the same input for different records is an SHA-384 collision in the journal chain (Lemma 9‴). The shipment direction is symmetric. □

Executed (nimbus-replica tests): replicas byte-identical to the engine's journal and able to take over, with signatures and with MACs; a shipment under another operator key refused and nothing stored; a bit flipped in an acknowledgement by a proxy, a liar that stores nothing and acknowledges the exact anchors under a wrong key, a wrong link secret and a wrong replica index all refused — with a quorum of two, nothing is released; a silent replica dropped by timeout, and by the in-flight cap. Over loopback TCP (tcp-bench, 1,500 slots of 8 orders, two replicas both required, 3 runs), release time after slot close, p50 / p99 in ms:

| slot | no replicas | Ed25519 links | HMAC links |
|---|---|---|---|
| 1 ms | 0.39 / 3.9 (3/3 stable) | 1.58 / 18.5 (3/3 stable) | 1.37 / 2.9 (3/3 stable) |
| 0.5 ms | 0.41 / 11.9 (3/3 stable) | 38.22 / 75.2 (0/3 stable) | 0.97 / 16.6 (2/3 stable) |

Replication adds ≈1.0 ms at p50 on loopback, against ≈0.1 ms in the model: per-hop processing — waking the sending, serving and acknowledging threads on a shared 4-vCPU host, and, with signatures, ≈176 µs of signing and verification — not the wire. With that processing as a term c_hop in the replication model (analysis/replication_hop_mc.py), the windowed reach at 150 entries/ms, two replicas both required (three of four), is 23 (30) km at c_hop = 0, 22 (28) km at 30 µs (HMAC, spinning I/O), 14 (18) km at 176 µs (signatures) and 0 at this VM's ≈1 ms. Link authentication should be HMAC and replication I/O must not sleep (O28). Timeout: with round trips LogNormal(ln(m + c_hop), 0.3²), τ = (m + c_hop)·e^{0.3z} drops a healthy replica with probability 1 − Φ(z) per batch (Monte Carlo agrees at 10⁻³ and 10⁻⁴); 10⁻¹² needs τ = 0.83 ms at 5 km and 2.06 ms at 20 km (c_hop = 30 µs).

**Polled replication I/O, executed.** Pipeline::attach_polled_windowed drives every replica from one thread that never sleeps (non-blocking sockets, TcpPoll), replica servers spin on non-blocking sockets (serve_one_spinning), and the engine waits for acknowledgements by spinning; the protocol, authentication and release rule are unchanged (Corollaries Z2, Z3; all transport tests run in both modes). tcp-bench, HMAC links, all replicas required, 1,500 slots of 8 orders, median of 3 runs; release time after slot close, p50 / p99 in ms (A: 1 replica, 0.5 ms slots, spin-pool verification; B: 2 replicas, 1 ms slots, no spin pool, so that the spinning threads fit this VM's four cores):

| configuration | no replicas | sleeping threads | polled I/O | stable (polled) |
|---|---|---|---|---|
| A: 1 replica, 0.5 ms | 0.28 / 4.6 | 0.74 / 5.9 | 0.24 / 5.5 | 3/3 |
| B: 2 replicas, 1 ms | 0.43 / 2.6 | 1.36 / 2.5 | 0.55 / 8.9 | 3/3 |

Polling removes the wake-ups that dominated each hop: the added median falls from ≈927 µs to ≈114 µs (B), and with one replica polled release matches the unreplicated engine at p50 (A). With c_hop = 114 µs the modelled windowed reach at 150 entries/ms is 18 km (2 of 2) and 22 km (3 of 4). The p99 column is set by this host's stalls (several ms with or without replicas); spinning costs one core per replica server and one I/O core per engine, and with more spinning threads than cores the engine falls behind (two replicas plus spin-pool verification on four vCPUs). Dedicated hosts with isolated cores (T12, T17) decide whether the polled hop fits the 1 ms budget at p99.

## 7 · Related Work

### 7.1 Lineage

Slow path descends from PBFT [1] (2/3 quorum, f<1/3) via HotStuff [2] and HotStuff-2's two-chain responsiveness [3]. Contrast Raft (CFT, no adversarial model — not applicable) and Nakamoto consensus (probabilistic, confirmation-depth finality vs. NIMBUS's deterministic certificates, at the cost of a known validator set). Tendermint: same single-path 2/3 family, no fast path.

### 7.2 Contemporary Protocols

Fast path: Votor pattern, Solana Alpenglow [project spec, not peer-reviewed] — single-round, 4/5 quorum. NIMBUS takes the certificate-race structure only; dissemination assumptions are its own (§3.3). Hyperliquid HyperBFT/HyperCore: closest production analog, sub-second finality, project documentation only (design comparator, not a citable source — Back Matter). Sui/Mysten: Horizon-0 host, source of the ≈390 ms baseline; object-centric execution is orthogonal to this consensus layer. Distinguishing claim: a proved unconditional slow-path fallback (Theorem A) racing a proved conditional fast path (Theorem B), not commitment to one quorum regime.

## 8 · Conclusion & Future Directions

### 8.1 Synthesis

Safety reduces, with no loss in the hash term, to collision resistance of an eighteen-domain SHA-384 registry and EUF-CMA signatures at f < 1/3 (Theorems A, A\*, B). Sub-millisecond finality is a conditional, simulated result whose conditions are now explicit: a metro validator set (≈78 km end-to-end, ≈99 km certificate-only), per-vote Ed25519 with k ≈ n/6 verification cores, streaming Merkle roots on 16 hashing cores, Δ_slot = 0.25 ms, three concurrent proposers against crashed leaders, skip certificates for shared-state ordering (≈40 km at b = 4), and ≥ 7 sites to ride out a data-centre outage. The reference engine adds two conditions for acknowledging a trade within the same millisecond: a durable flush ≤ 50 µs and latency-mode signature batching (§6.6). Each condition is a falsifiable hardware test (App. C).

### 8.2 Open Problems

- **O1.** Unconditional existence of classical OWFs.
- **O2.** P≠NP ⇒ OWF.
- **O4.** Fast-path liveness, live stake <4/5.
- **O5.** Post-quantum Σ — *quantified* (§6.4): ML-DSA-44 keeps 1 ms to n ≤ 52 at 41 KB certificates; SLH-DSA only on the slow path. Hash side closed: SHA-384 commitments (Prop. Q′). Open: aggregation for lattice signatures.
- **O6.** Proper-score calibration of K on a long certified prefix.
- **O8.** Formalize predicate R (Def. 15) as a class; characterize non-vacuous Corollary 18 bounds vs. detection latency.
- **O9.** Empirical failure-mode comparison, certified vs. uncertified agents, capability held fixed.
- **O10.** Formal liveness proof under §2.1's partial synchrony (§4.2 is policy, not theorem).
- **O11.** Coalition formation across repeated play: derive f<1/3 from stake-acquisition cost and the folk-theorem patient-player regime of Corollary 25B, not assume it (Prop. 24 covers only single-slot best-response).
- **O12.** Formal MEV analysis of VRF leader-ordering power.
- **O13.** Sybil resistance beyond stake-weighted quorum (§2.2).
- **O14.** Static-vs-adaptive corruption (§2.2 reductions are static).
- **O15.** Network topology/peer-discovery beyond the colo-clique case (§6.2).
- **O16.** Founder sign-off on Candidate 27's split ratios; derive incentive-compatibility beyond Proposition 24's base-signing scope.
- **O17.** Empirical testbed on real infrastructure — the largest remaining gap; Appendix C specifies seventeen acceptance tests with pass thresholds.
- **O18.** Whether §6.4's sub-millisecond single-metro topology is worth its decentralization cost — a design decision, not a technical one, left open.
- **O21.** Sub-ms verification — *resolved by alternative* (§6.4): per-vote Ed25519 on arrival. Open remainder: whether hardware BLS pairing keeps constant-size certificates under 1 ms — needed beyond ≈100 validators, where per-vote verification exceeds the budget.
- **O23.** Pipelining — *resolved for fast-path finality* (Thm. A″, Prop. N: f < n/5). Open: pipelining with f ∈ [n/5, n/3). Message cost bounded (Prop. O).
- **O24.** Stake cap (§6.4): choose a per-validator ceiling that keeps the safety Nakamoto coefficient ≥ 4 and the fast-path coefficient ≥ 2; skew costs latency as well as decentralization.
- **O25.** Ordering finality under K concurrent proposers — *resolved to ≈40 km* by fast skip certificates with slow-path fallback (Prop. U); open beyond 40 km with b = n/5 − 1 crashed.
- **O26.** Engine acknowledgement within 1 ms (§6.6): needs a ≤ 50 µs durable flush (T13), latency-mode batching, cross-slot pipelining and replicas within the reach of Proposition Z⁗ (T15); capacity then scales with verification cores (T14) on never-sleeping workers (T16). Quorum replication, blocking and windowed, is implemented (v0.8, v0.9), over authenticated TCP (v0.10).
- **O27.** Bridge trust: k-of-m bridge keys and per-slot deposit caps bound a single-key compromise; settlement pays only against proven receipts, once, under checkpoints co-signed by certifiers that re-execute the replicated journal (Prop. Z‴, Cor. Z6; implemented v0.13). Open: custody of the k bridge keys and of certifier keys.
- **O28.** Replication hop: polled, never-sleeping I/O (v0.11) cuts the measured per-hop cost on a shared VM from ≈1 ms to ≈114 µs at p50 (§6.6); open: p99 on dedicated hosts with isolated cores and a real link (T17).
- **O29.** Verification dispatch: spinning workers cut 8-signature dispatch from 434–489 to 155–173 µs (p50), but p99 on this shared VM is 619–1835 µs; whether reserved, isolated cores bring p99 within the slot budget is T16.
- **O30.** Restart — *resolved* for certifiers (v0.16, Prop. Z8) and the engine (v0.17, Prop. Z9): O(state + suffix + log history) instead of O(history). Open: catch-up needs λ < r_c (r_c/r_e = 0.92–1.08 measured); starting from another node's snapshot needs a state root in the 0x0C body; the follower needs cores of its own (measured: slot p50 +27% when it shares four).
Closed during v3 and removed from the list: O7, O20, O22 (companion hash retired, Appendix A), O19 (BLS benchmarked, §6.4); O3 is merged into O17.

## References

Peer-reviewed/archived sources, IEEE-numbered. Project documentation cited separately below.

[1] M. Castro and B. Liskov, “Practical Byzantine Fault Tolerance,” in *Proc. 3rd USENIX Symp. Operating Systems Design and Implementation (OSDI)*, 1999.

[2] M. Yin, D. Malkhi, M. K. Reiter, G. G. Gueta, and I. Abraham, “HotStuff: BFT Consensus in the Lens of Blockchain,” in *Proc. ACM Symp. Principles of Distributed Computing (PODC)*, 2019.

[3] D. Malkhi and K. Nayak, “HotStuff-2: Optimal Two-Phase Responsive BFT,” *IACR ePrint*, 2023/397, 2023.

[4] C. Dwork, N. Lynch, and L. Stockmeyer, “Consensus in the Presence of Partial Synchrony,” *J. ACM*, vol. 35, no. 2, pp. 288–323, 1988.

[5] O. Goldreich, *Foundations of Cryptography: Volume 1, Basic Tools*. Cambridge Univ. Press, 2001.

[6] R. Impagliazzo, “A Personal View of Average-Case Complexity,” in *Proc. 10th Structure in Complexity Theory Conf.*, 1995.

[7] P. Rogaway and T. Shrimpton, “Cryptographic Hash-Function Basics: Definitions, Implications, and Separations for Preimage Resistance, Second-Preimage Resistance, and Collision Resistance,” in *Proc. Fast Software Encryption (FSE)*, 2004.

[8] R. C. Merkle, “A Digital Signature Based on a Conventional Encryption Function,” in *Proc. CRYPTO*, 1987.

[9] D. Boneh, B. Lynn, and H. Shacham, “Short Signatures from the Weil Pairing,” in *Proc. ASIACRYPT*, 2001.

[10] M. Viazovska, “The Sphere Packing Problem in Dimension 8,” *Annals of Mathematics*, vol. 185, no. 3, pp. 991–1015, 2017.

[11] H. Cohn, A. Kumar, S. D. Miller, D. Radchenko, and M. Viazovska, “The Sphere Packing Problem in Dimension 24,” *Annals of Mathematics*, vol. 185, no. 3, pp. 1017–1033, 2017.

[12] B. Green and T. Tao, “The Primes Contain Arbitrarily Long Arithmetic Progressions,” *Annals of Mathematics*, vol. 167, no. 2, pp. 481–547, 2008.

[13] D. Amodei, C. Olah, J. Steinhardt, P. Christiano, J. Schulman, and D. Mané, “Concrete Problems in AI Safety,” *arXiv:1606.06565*, 2016.

[14] E. Hubinger, C. van Merwijk, V. Mikulik, J. Skalse, and S. Garrabrant, “Risks from Learned Optimization in Advanced Machine Learning Systems,” *arXiv:1906.01820*, 2019.

[15] Y. Bengio *et al.*, “Managing Extreme AI Risks Amid Rapid Progress,” *Science*, vol. 384, no. 6698, pp. 842–845, 2024.

[16] D. Fudenberg and E. Maskin, “The Folk Theorem in Repeated Games with Discounting or with Incomplete Information,” *Econometrica*, vol. 54, no. 3, pp. 533–554, 1986.

[17] W. Diffie and M. E. Hellman, “Exhaustive Cryptanalysis of the NBS Data Encryption Standard,” *IEEE Computer*, vol. 10, no. 6, pp. 74–84, 1977.

[18] E. R. Berlekamp, “Factoring Polynomials Over Finite Fields,” *Bell System Technical Journal*, vol. 46, no. 8, pp. 1853–1859, 1967.

[19] D. Shanks, “Class Number, a Theory of Factorization, and Genera,” in *Proc. Symposia in Pure Mathematics*, vol. 20, American Mathematical Society, 1971, pp. 415–440.

[20] D. Chaum, E. van Heijst, and B. Pfitzmann, “Cryptographically Strong Undeniable Signatures, Unconditionally Secure for the Signer,” in *Proc. CRYPTO ’91*, LNCS 576, Springer, 1992, pp. 470–484.

[21] D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, and B.-Y. Yang, “High-Speed High-Security Signatures,” *Journal of Cryptographic Engineering*, vol. 2, no. 2, pp. 77–89, 2012.

[22] D. M. Gordon, “Discrete Logarithms in GF(p) Using the Number Field Sieve,” *SIAM Journal on Discrete Mathematics*, vol. 6, no. 1, pp. 124–138, 1993.

[23] B. Laurie, A. Langley, and E. Kasper, “Certificate Transparency,” RFC 6962, IETF, 2013.

[24] G. Brassard, P. Høyer, and A. Tapp, “Quantum Cryptanalysis of Hash and Claw-Free Functions,” LATIN 1998, LNCS 1380, pp. 163–169.

[25] M. Zhandry, “A Note on the Quantum Collision and Set Equality Problems,” *Quantum Information & Computation*, vol. 15, no. 7–8, pp. 557–567, 2015.

[26] S. Josefsson and I. Liusvaara, “Edwards-Curve Digital Signature Algorithm (EdDSA),” RFC 8032, IETF, 2017.

[27] K. Chalkias, F. Garillot, and V. Nikolaenko, “Taming the Many EdDSAs,” in *Security Standardisation Research (SSR 2020)*, LNCS 12529, pp. 67–90, 2020.

> **PROJECT DOCUMENTATION (NOT PEER-REVIEWED).** Solana Labs, Alpenglow spec (Votor/Rotor), 2025. Hyperliquid, HyperBFT/HyperCore docs. Sui/Mysten Labs, finality docs (≈390 ms). Nimbus One-Way Hash Function — companion thesis (this project); cryptanalysis in Appendix A retires it from §2.3 (Propositions E, I; Theorem H).

## Appendix A — Companion Hash Candidates

Theorem A requires a collision-resistant Hκ (Conjecture 1). This appendix evaluates the project's companion construction against that requirement. v1: sᵢ = sᵢ₋₁(1+xᵢ) + xᵢpᵢ mod q (q prime, pᵢ from Green–Tao progressions [12]). v2: sᵢ = g^((sᵢ₋₁+xᵢ) mod q) mod p (g of prime order q, p = 2q+1). Input x = (x₁,…,xₘ); s₀ and all pᵢ public.

> **PROPOSITION E (v1 is invertible per step).** If (1+xᵢ) ≢ 0 mod q, then sᵢ₋₁ = (sᵢ − xᵢpᵢ)(1+xᵢ)⁻¹ mod q.

> *Proof.* Rearrange and multiply by the inverse of (1+xᵢ), which exists since q is prime. Checked on 200,000 random instances at 61-bit q: 100% exact recovery. □

> **COROLLARY E1 (meet-in-the-middle on v1).** Preimage search over x costs O(q^⌈m/2⌉) time and space instead of O(q^m) [17]: forward table from s₀ over x₁…x_⌈m/2⌉, backward table from sₘ via Proposition E, intersect. An m-step chain sized for λ bits against brute force retains ≈λ/2.

> *Proof.* q=41, m=6: q^m = 4.75×10⁹ vs 2q^(m/2) = 137,842 (ratio 34,460 = closed form); valid preimage recovered in 0.06 s. □

> **PROPOSITION E′ (every fixed-degree polynomial step is invertible).** For sᵢ = P_d(sᵢ₋₁; xᵢ, pᵢ) mod q with deg P_d = d fixed, all ≤ d predecessors of sᵢ are computable in poly(d, log q) time by root-finding over F_q [18]. Non-bijectivity (d ≥ 2) does not prevent inversion.

> *Proof.* Berlekamp / Cantor–Zassenhaus root-finding [18]. Checked at d=2 (sᵢ = sᵢ₋₁² + xᵢsᵢ₋₁ + pᵢ, quadratic formula with Tonelli–Shanks): 50,000 trials at 61-bit q, true predecessor among the ≤2 roots in 100%. □

> **PROPOSITION G (v2 single-step cost).** Inverting one v2 step is a discrete logarithm in ⟨g⟩: Θ(√q) for generic algorithms (baby-step giant-step [19], Pollard rho). In ⟨g⟩ ⊂ Z_p\* the number field sieve runs in L_p[1/3, (64/9)^{1/3}] [22], so p must be ≈3072 bits for 128-bit security, or v2 must be instantiated on an elliptic-curve group. *Erratum: v3.0 stated that no sub-exponential algorithm applies to safe-prime subgroups; that is false in Z_p\*.*

> *Proof.* BSGS at q = 16/20/24/28 bits: table size 246 → 872 → 3,026 → 15,602, successive ratios equal to √(q_{k+1}/q_k); every inverse correct. □

*Figure 10. Single-step inversion cost: constant for v1 (Proposition E), √q for v2 (Proposition G).*

> **THEOREM H (inverting v2 ≡ DLP in ⟨g⟩, for all m).** Any v2 preimage-finder yields a DLP solver with one call, and vice versa. The chain length m contributes no one-wayness: v2 is exactly as hard to invert as x ↦ g^x.

> *Proof.* (⇐) Choose x₁…xₘ₋₁ freely, compute sₘ₋₁, set xₘ = (log_g sₘ − sₘ₋₁) mod q. (⇒) Given y = g^e with e uniform, pose y as sₘ; it is distributed as a real output because sₘ₋₁+xₘ is uniform mod q; a returned x′ gives e = (s′ₘ₋₁ + x′ₘ) mod q. Checked for m ∈ {2,4,8,16,64} at 32-bit q: one DLP per preimage, 71k–122k group operations regardless of m. □

> **PROPOSITION I (v2 is not collision resistant).** For m ≥ 2 and any x, set x′₁…x′ₘ₋₁ ≠ x₁…xₘ₋₁ freely and x′ₘ = (sₘ₋₁ + xₘ − s′ₘ₋₁) mod q. Then x′ ≠ x and both map to sₘ, in O(m) exponentiations and no DLP.

> *Proof.* 1,000/1,000 valid collisions at 128-bit q, m=8, 1.29 ms each. □

> **PROPOSITION J (contrast: CvHP is collision resistant under DLP).** h(a,b) = g^a·h^b mod p with log_g h unknown [20]. A collision (a,b) ≠ (a′,b′) yields log_g h = (a−a′)(b′−b)⁻¹ mod q. v2 fails where CvHP succeeds because xₘ and sₘ₋₁ share one exponent additively; CvHP binds inputs to independent bases.

> *Proof.* 28-bit q: birthday collision after 9,094 evaluations (√q = 12,081); the recovered log_g h equals the secret. At 3072-bit p: 153 ms per compression (≈5 KB/s) vs SHA-256 at 421 MB/s — ratio ≈8.4×10⁴. □

*Figure 11. Throughput: provably collision-resistant CvHP at NFS-safe size vs SHA-256 (log scale).*

| candidate | one-way | collision resistant | throughput | role in §2.3 |
|---|---|---|---|---|
| v1 (affine) and any fixed-degree polynomial step | no (Prop. E, E′) | no | — | excluded |
| v2 (exponent chain) | iff DLP (Thm. H) | no (Prop. I) | — | excluded |
| CvHP | yes, under DLP | yes, under DLP (Prop. J) | ≈5 KB/s | too slow |
| SHA-2 / SHA-3 / BLAKE2b | conjectured | conjectured (Conj. 1); Cor. 13′ | 421 MB/s (SHA-256) | **SHA-384 used** |

⚠ **OUTCOME.** Neither companion variant satisfies Conjecture 1; the one construction here that provably does (CvHP) is ≈8.4×10⁴ slower than SHA-256, against a 1.28×10⁵ ops/s Merkle pipeline. The companion candidate is retired; §2.3 keeps standard hashes. O7, O20, O22 resolved.

## Appendix B — Encoding Lemmas and Hash Commitments

### B.1 Encoding Lemmas and Derivations

> **LEMMA 9.** Under the domain-separated encoding of §3.1, distinct batches with equal roots yield u≠v with Hκ(u)=Hκ(v).

> *Proof.* Walk from the root toward the first position where the batches differ. At each node the two hash inputs either differ — an Hκ collision — or are equal, in which case the children (fixed-length λ-bit digests, so the split point is unique) are equal and the walk continues. If one tree reaches a leaf where the other has an internal node (batches of different length give different shapes), the inputs carry different prefixes (0x00 vs 0x01) and therefore differ: again a collision. Since the batches differ, the walk terminates in a collision. □

> **ERRATUM (v3.0–v3.2).** The earlier definition, Hκ(a∥b) with no prefixes, falsifies Lemma 9 in two ways. (i) Depth confusion: for a batch with leaf digests d₁…d₄, the 2-leaf batch B′ = (d₁∥d₂, d₃∥d₄) (two 64-byte encodings, within ℓ = 96 B) has the same root. (ii) If leaves are unhashed variable-length strings, a∥b = a′∥b′ for a different split point. Either gives two batches under one certified root with no collision, so honest replicas could execute different batches — a safety failure outside Theorem A's assumptions. Executed: 10,000/10,000 forgeries for (i) and for (ii) under the old encoding; 0/10,000 for (i) with 0x00/0x01 prefixes.

**Lemma 9, executed.** The proof is an extractor: follow the path to the first differing leaf and return the first node whose child-concatenation differs while its hash matches. Run on 8-leaf Merkle trees with SHA-256 truncated to k bits: root collisions appeared after 311 / 1,088 / 5,002 trees at k = 16 / 20 / 24 (birthday prediction √(π/2)·2^(k/2) = 321 / 1,284 / 5,134), and the extractor returned a genuine H-collision in 48 of 48 cases.

*Figure 12. Trees built before a Merkle-root collision, against the birthday bound. Every collision reduced to a hash collision, as Lemma 9 requires.*

> **LEMMA 9′ (header-chain binding).** Under §3.1's encoding, two distinct header chains (h_1…h_t), (h′_1…h′_t) from the unique genesis with h_t = h′_t yield u ≠ v with Hκ(u) = Hκ(v). The extractor costs ≤ t header comparisons plus Lemma 9 on the first differing batch, and succeeds with probability 1.

> *Proof.* Walk back from slot t. Equal outputs with different inputs are a collision. Equal inputs (0x02 ∥ t ∥ r ∥ h) give equal roots and equal predecessors; continue. The chains differ, so some slot has different inputs, or equal headers with batches B ≠ B′ under one root — Lemma 9. The 0x02 prefix and the fixed-length fields make a header input distinct from every leaf (0x00) and node (0x01) input, so a header cannot be reinterpreted as a Merkle node. This is Theorem A's "parent pointers differ" case made concrete. □

**Lemma 9′, executed.** 4-slot header chains with SHA-384 truncated to k bits: head collisions after 314 / 1,283 / 5,018 chains at k = 16 / 20 / 24 (birthday prediction 321 / 1,283 / 5,134; 12 runs each), and the extractor returned a genuine H-collision in 36 of 36 cases. Cost: one extra hash per slot.

> **LEMMA 9″ (domain registry: global injectivity).** Let every Hκ input be enc(d, f) = d ∥ f with the domain byte d and field layout of the table below. Then enc is injective on all (d, f) pairs, so Hκ(enc(d, f)) = Hκ(enc(d′, f′)) with (d, f) ≠ (d′, f′) is an Hκ collision. Every binding statement in this paper (Lemmas 9, 9′; Propositions Q, U, V, W, X, Z, Z‴; Corollary Z3) is an instance.

> *Proof.* d = d′ is forced by the first byte. Within a domain, fields are fixed-length, or carry the injective operation encoding of §3.1 (0x00), a length prefix (0x0B: the entry length precedes the entry, whose own kind byte fixes its layout), or a self-delimiting encoding (0x0D: source, market, status and balance tags and the fill count fix every field length), so f is recovered uniquely from the remaining bytes. □

| d | domain | fields after d | input bytes (SHA-384) |
|---|---|---|---|
| 0x00 | batch leaf | encode(op) | 1 + |op| ≤ 97 |
| 0x01 | batch node | left ∥ right | 97 |
| 0x02 | header | t ∥ j ∥ root ∥ h_prev ∥ A_{t−L} | 154 |
| 0x03 | skip root r_⊥ | t ∥ j | 10 |
| 0x04 | history leaf | header | 155 |
| 0x05 | history node | left ∥ right | 97 |
| 0x06 | state leaf | key ∥ value | 41 |
| 0x07 | state node | left ∥ right | 97 |
| 0x08 | timeout statement (signed) | t ∥ j ∥ reported vote digest | 58 |
| 0x09 | client order (signed) | market ∥ acct ∥ side ∥ price ∥ qty ∥ tif (0–3) ∥ nonce ∥ expiry ∥ 0 | 44 |
| 0x0A | feed observation (signed) | market ∥ price ∥ slot ∥ time | 29 |
| 0x0B | journal link | chain_{i−1} ∥ len ∥ seq ∥ slot ∥ entry | 67 + len (208 for an order) |
| 0x0C | engine checkpoint (signed; co-signed by validators) | slot ∥ journal len ∥ journal head ∥ receipts root ∥ count | 121 |
| 0x0D | receipt leaf | slot ∥ source ∥ acct ∥ market? ∥ status ∥ balance? | ≥ 25; 281 for a one-fill taker receipt (fees and rebate included) |
| 0x0E | receipt node | left ∥ right | 97 |
| 0x0F | account action (signed) | kind ∥ market ∥ acct ∥ nonce ∥ expiry ∥ order id ∥ base ∥ quote | 66 |
| 0x10 | bridge operation (k-of-m signed) | kind ∥ reference ∥ expiry ∥ market ∥ acct ∥ base ∥ quote ∥ key | 114 |
| 0x11 | replication statement (signed or MAC) | role ∥ replica ∥ from len ∥ from head ∥ to len ∥ to head | 116 |
| 0x12 | replay snapshot (local integrity seal) | version ∥ last slot? ∥ journal len ∥ head ∥ bytes ∥ admission ∥ markets ∥ expiries ∥ window | ≥ 160 |

Executed (consensus domains 0x00–0x08): 200,000 random inputs across all nine domains parse back to their (d, f) — no two distinct pairs share an input — and 0 of 50,000 inputs built for one domain parse as another. Because every signed statement signs a registry digest, injectivity also types signatures: of 50,000 attempted cross-type replays (proposal vote or skip vote presented as a timeout statement, proposal vote presented as a skip vote), Ed25519 accepted 0; a success would require an Hκ collision or a forgery. A SHA-384 block carries ≤ 111 input bytes after padding: every input is one block except the header and history leaf (2 blocks each, once per (t, j)). **Engine domains, executed** (analysis/registry18.py, reading only this table): all 16 inputs emitted by nimbus-core for 0x09–0x12 (including a maker receipt, the three replication roles and a replay snapshot, which also anchors at the code's journal) parse under their row, consuming every byte, re-encode identically and hash to the code's digests; the code's journal re-chains from H(0x0B ∥ "genesis") to the head in its signed checkpoint; 250,000 random field tuples (25,000 per domain) round-trip exactly with 0 shared inputs. Some receipt bodies also parse as a feed observation, a checkpoint body or a receipt-node body — there the domain byte alone separates them, which is the content of the lemma. 0x09, 0x0A, 0x0E and 0x0F inputs are one SHA-384 block; 0x0B, 0x0C, 0x10, 0x11 and most receipts two.

> **LEMMA 9‴ (journal and receipt binding).** Two distinct journals J ≠ J′ of equal length from the genesis link H(0x0B ∥ "genesis") with equal heads yield u ≠ v with H(u) = H(v); the extractor makes at most |J| comparisons. Hence an engine checkpoint binds its journal prefix, and — by Lemma 9 on the 0x0D/0x0E tree — its receipt set.

> *Proof.* Walk back from the head. At link i the inputs are 0x0B ∥ c_{i−1} ∥ len ∥ seq ∥ slot ∥ entry. If they differ, equal outputs are a collision. If they are equal, the length prefix makes the split between c_{i−1} and the record unique (Lemma 9″), so the records and the predecessors are equal; continue. The journals differ, so some link has different inputs. □

**Lemma 9‴, executed** (analysis/journal_extractor.py). Four-record journals in the engine's record layout, SHA-384 truncated to k bits: head collisions after 348 / 1,489 / 5,130 journals at k = 16 / 20 / 24 (birthday prediction 321 / 1,283 / 5,134; 12 runs each), and the extractor returned a genuine H-collision in 36 of 36 cases.

**Shred volume.** 384 KB at coding rate 3/2 → 576 KB coded. At 10 Gbps: 576,000 B × 8 / 10×10⁹ b/s ≈ 0.46 ms serialization, confirming the <0.5 ms figure in §3.3/§6.2. **Encoding ceiling, worked.** ℓ=96 B ⇒ 393,216 B / 96 B = 4096 ops/slot (floor). Slot duration 32 ms ⇒ 1000/32 = 31.25 slots/s. 4096 × 31.25 = 128,000 = 1.28×10⁵ ops/s. **Clique edges.** Kₙ = n(n−1)/2: n=21 ⇒ 210; n=64 ⇒ 2016.

### B.2 Hash Commitments: Concrete Security, Light Clients and History

> **PROPOSITION Q (multi-target inclusion-proof security).** Model H as a random oracle with λ-bit output and RFC 6962 prefixes. Let the chain hold R honest roots over trees of ≤ m leaves, so at most T = R(2m − 1) honest node digests exist. An adversary making q oracle queries outputs a proof that a leaf x ∉ B_r is included under honest root r with probability ≤ qT/2^λ + q²/2^(λ+1).

> *Proof.* Recompute the claimed path from x toward r. The recomputed value at the root equals r; at the leaf it differs from every honest leaf digest at that position, or else x (with prefix 0x00) is a preimage of an honest leaf digest from a different input — a hit on a target. Let v be the lowest path node whose recomputed value equals the honest value while its recomputed input differs from the honest input. v exists because the inputs differ at the leaf and the values agree at the root. The prefix byte fixes the node type, so v's query is an internal (or leaf) query whose output lies in the honest target set with a non-honest input. Two cases: the adversary queried v's input before the honest digest was fixed, which is a collision among ≤ q queries (≤ q²/2^(λ+1)); otherwise each fresh query lands in a fixed set of ≤ T values with probability ≤ T/2^λ, and a union bound over q queries gives qT/2^λ. □

| regime | R (roots) | T = R(2m−1) | classical bound, q = 2^80 | quantum (multi-target Grover) work |
|---|---|---|---|---|
| 32 ms slots, 10 yr, m = 4,096 | 2^33.2 | 2^46.2 | 2^−129.8 | ≈2^104.9 |
| 1 ms slots, 10 yr, m = 4,096 | 2^38.2 | 2^51.2 | 2^−124.8 | ≈2^102.4 |
| 1 ms slots, 100 yr, m = 2^16 | 2^41.5 | 2^58.5 | 2^−117.5 | ≈2^98.7 |

The collision term q²/2^257 = 2^−97 dominates at q = 2^80, so pipelining to 1 ms slots costs inclusion proofs ≈5 bits and leaves the Corollary 13′ bound unchanged. Monte Carlo check (truncated SHA-256, k = 22 bits, 40 searches per row): mean queries to first target hit / predicted 2^k/T = 1.26, 1.03, 1.06, 1.01, 1.11 for T = 15, 60, 240, 1,008, 4,032 (standard error ≈16% per row) — the 1/T scaling in the proof holds.

> **PROPOSITION Q′ (quantum adversary; choice of λ).** Against Q quantum queries to a random oracle with λ-bit output, collision probability is Θ(Q³/2^λ) [24, 25] and multi-target preimage probability is O(Q²T/2^λ) (Grover). Theorem A's hash term is therefore ≈Q³/2^λ quantumly: at Q = 2^80 this is ≈2^−16 for λ = 256 and ≈2^−144 for λ = 384. Classical security at λ = 384 is q²/2^385 = 2^−225 at q = 2^80.

> *Proof.* Substitute the quantum collision bound for the birthday bound in Corollary 13′; the extractor of Lemma 9 is classical post-processing of the adversary's output and is unchanged. Constants are omitted; the figures are orders of magnitude. □

| instantiation | node input | t_h (measured) | collision term, Q = 2^80 quantum | proof size (m = 4,096) | Merkle tail D_k, k = 8 / 16 |
|---|---|---|---|---|---|
| SHA-256 (λ = 256) | 65 B | 0.22–0.23 µs | ≈2^−16 | 384 B | 3.6 / 3.0 µs |
| SHA-384 (λ = 384) | 97 B | 0.40 µs | ≈2^−144 | 576 B | 15.6 / 5.2 µs |
| SHA3-384 (λ = 384) | 97 B | 0.57 µs | ≈2^−144 | 576 B | 53.3 / 9.7 µs (R″) |

OpenSSL 3 EVP, same host as Proposition P; SHA-384 fits a 97-byte node in one 128-byte block. Tails: event simulation, random arrival order, 120 batches (SHA-256, SHA-384); SHA3-384 from Proposition R″. Moving Hκ to SHA-384 costs 1.7× hashing work, 8 → 16 hashing cores for the same tail, and 192 B per inclusion proof; it adds ≈2 µs at k = 16 and no measurable distance. We therefore specify SHA-384 for Merkle commitments, closing the hash half of O5.

> **PROPOSITION V (succinct finality proof for light clients).** A proof that operation x is final at (t, j) is π_x = (x, sibling path P, header h_{t,j}, certificate γ). The client checks that P hashes x to root(B_{t,j}) under the 0x00/0x01 prefixes, that the header encodes that root, and that γ holds ⌈0.8n⌉ valid signatures on h_{t,j}. A client that accepts is wrong with probability ≤ Adv^Forge (Theorem A\*) + Adv^incl (Proposition Q). Proof size is 64⌈0.8n⌉ + ⌈n/8⌉ + 154 + λ/8·⌈log₂(m/K)⌉ bytes; verification costs ⌈0.8n⌉ signature checks and ⌈log₂(m/K)⌉ + 2 hashes.

> *Proof.* If x is not in the batch honest validators certified at (t, j), an accepting proof either carries a valid certificate on a header honest validators did not certify — a Theorem A forgery, since honest nodes certify one header per (t, j) — or a valid path from x to the honest root with x ∉ B_{t,j}, bounded by Proposition Q. The two events cover every accepting false proof; a union bound gives the sum. Sizes: 64-byte signatures, a signer bitmap, the 154-byte header (1 + 8 + 1 + 48 + 48 + 48) and one 48-byte sibling per level. □

| n | certificate | header | path (m/K = 1,366) | total | verify, 1 core / 4 cores | hashing |
|---|---|---|---|---|---|---|
| 21 | 1,091 B | 154 B | 528 B | **1.77 KB** | 1.07 / 0.27 ms | 5.2 µs |
| 64 | 3,336 B | 154 B | 528 B | 4.02 KB | 3.28 / 0.82 ms | 5.2 µs |
| 100 | 5,133 B | 154 B | 528 B | 5.82 KB | 5.04 / 1.26 ms | 5.2 µs |

Unit costs: Ed25519 0.063 ms, SHA-384 0.398 µs. Signatures are 95% of bytes and > 99% of verification time, so an aggregate or threshold signature on headers is the lever for light clients — one that consensus itself cannot use at 1 ms (Proposition L), since a light client has no 1 ms deadline.

> **PROPOSITION W (header-history accumulator).** Let A_t = MTH over the certified headers h_1 … h_t in certification order, with leaf prefix 0x04 and node prefix 0x05, maintained by the frontier of Proposition R. (i) Two distinct histories with A_t = A′_t yield an Hκ collision. (ii) No accumulator digest equals a leaf, node, header or skip digest (prefixes 0x00–0x03) without a collision. (iii) Membership of any past header costs ⌈log₂ t⌉ siblings. (iv) Appending costs 2 − 1/t hashes amortized; the fold is ≤ ⌈log₂ t⌉ hashes, done once per slot.

> *Proof.* (i) Lemma 9 with 0x04/0x05 in place of 0x00/0x01: the walk from the root ends at differing inputs with equal outputs. (ii) The first byte of every hash input fixes its type. (iii)–(iv) Proposition R (ii)–(iii) applied to the header sequence. □

| chain age (K = 3, 1 ms slots; proving the oldest operation) | walk back header by header | accumulator path (Prop. W) |
|---|---|---|
| 1 day | 27.5 GB | 1.34 KB (28 siblings) |
| 1 year | 10.0 TB | 1.78 KB (37 siblings) |
| 10 years (t = 9.5·10¹¹ headers) | 100 TB | **1.92 KB (40 siblings)** |

Executed with SHA-384: frontier root = recursive MTH in 339/339 histories (t ≤ 5,000), every membership proof verified, none exceeded ⌈log₂ t⌉ siblings, 1.996 hashes per appended header; on 16- and 20-bit truncations the Lemma 9 extractor returned a genuine collision from 20/20 accumulator-root collisions. A complete proof that an operation of any age is final is π_x (Proposition V) plus one accumulator path. Built and verified end to end (n = 21, 11-level batch path, 40-level accumulator path): **3,789 bytes, 1.09 ms median verification on one core** (PyNaCl/libsodium + hashlib; p99 2.1 ms on a shared host). The header grows by 48 bytes. Negative test: of 6,000 proofs with one mutation each — a flipped byte in the operation, batch path, header, signature or accumulator path; a flipped path side; one signature short; a duplicated or wrong signer; an accumulator path replayed as a batch path; a header re-prefixed 0x01 — the verifier accepted 0 (200/200 valid proofs accepted).

## Appendix C — Testbed Acceptance Protocol (O17)

Each simulated claim becomes a falsifiable hardware test. Setup: n = 21 servers (4 verification + 16 hashing cores, SHA-NI), 100 GbE kernel-bypass NICs, sites per the placement column; ≥10⁶ slots per test, latency measured at every validator with PTP-synchronized clocks (≤ 1 µs error). A test passes if the measured value is within the tolerance of the prediction; a failure falsifies the named model component.

| ID | test | configuration | simulated prediction | pass if | failure falsifies |
|---|---|---|---|---|---|
| T1 | verification service time | 1 core, Ed25519, 10⁶ verifies | mean 0.063, p99 0.099 ms | within ±20% | service-time samples |
| T2 | zero-distance floor | one rack, b = 0 | p99 t_fin 0.385 ms (k = 4) | ≤ 0.45 ms | Prop. L queueing model |
| T3 | jitter σ | measure one-way lognormal fit | σ ≤ 0.3 assumed | fitted σ ≤ 0.3 | the distance budgets |
| T4 | Merkle tail | m = 4,096, SHA-384, k = 16 | D_k 5.2 µs | ≤ 10 µs | Props. R–R″ |
| T5 | certificate latency | metro sites ≤ 100 km across | p99 t_fin ≤ 1 ms | p99 ≤ 1.05 ms | geometric model |
| T6 | end-to-end latency | ≤ 78 km, Δ_slot = 0.25 ms | p99 t_e2e ≤ 1 ms | p99 ≤ 1.05 ms | reference design |
| T7 | withholding | b = 4 silent, ≤ 51 km | p99 t_e2e ≤ 1 ms | p99 ≤ 1.05 ms | fast-path tail model |
| T8 | site loss | 7 sites, one down, ≤ 62 km | p99 t_e2e ≤ 1 ms | p99 ≤ 1.05 ms | correlated-failure model |
| T9 | safety under attack | f = 4 Byzantine, Rule V+, 10⁶ slots | 0 conflicting commits | 0 violations | Theorems A, A″ |
| T10 | bandwidth | Δ_slot = 0.25 ms, 576 KB batches | 18.4 Gbps per validator | ≤ 25 Gbps | Prop. O |
| T11 | execution + state root | 4 × 10⁶ ops/s, D = 24, E = 32 ms | ≤ 13 hashing cores; exec ≤ 0.2 ms/batch | within ±25% | Prop. X |
| T12 | host stall budget | isolated validator cores, all loaded | ≤ 0.17 stalls/core-ms > 5 µs; p99 stall ≤ 50 µs | ≤ target | stall-injected envelope (§6.4) |
| T13 | durable flush | engine journal, 128-order group commit, 10⁶ commits | p99 ≤ 50 µs needed | p99 ≤ 50 µs | engine 1 ms acknowledgement (Prop. Z′) |
| T14 | engine latency | Δ_slot = 0.25 ms, k = 16, latency batching, 80 entries/ms | p99 ack ≤ 1 ms | p99 ≤ 1.05 ms | §6.6 engine model |
| T15 | replicated acknowledgement | T14 plus 2 replicas (need 2) at 5 km, 25 GbE, same flush | p99 ack ≤ 1 ms at 150 entries/ms | p99 ≤ 1.05 ms | Prop. Z⁗ network model |
| T16 | verification dispatch | 8-signature slots every 0.25 ms, spin pool on reserved isolated cores | p50 ≈ 0.16 ms (this VM) | p99 ≤ 0.25 ms | dispatch term (§6.6) |
| T17 | replication hop | engine and 2 replicas on separate hosts, 1 km, HMAC links, spinning I/O | c_hop ≈ 30 µs (assumed) | p99 ack − RTT ≤ 60 µs | Cor. Z3 reach (§6.6) |

T1–T4 need one rack and no WAN; they test the components every distance figure depends on and should run first. T9 is the only safety test and must pass irrespective of latency results.

## Appendix D — Latency Evidence for §6.4

### D.1 Jitter Sensitivity

**Jitter sensitivity at T = 1 ms** (Ed25519, 4 cores, 100 GbE, n = 21; 15,000-slot verification):

| σ | max one-way median | distance budget | p99 / mean at threshold |
|---|---|---|---|
| 0.1 | 0.330 ms | 65.9 km | 1.001 / 0.956 ms |
| 0.3 (baseline) | 0.313 ms | 62.6 km | 0.999 / 0.889 ms |
| 0.5 | 0.242 ms | 48.4 km | 1.006 / 0.804 ms |
| 0.7 | 0.183 ms | 36.5 km | 1.010 / 0.732 ms |
| 1.0 | 0.124 ms | 24.7 km | 0.995 / 0.671 ms |

The budget falls 2.7× from σ = 0.1 to 1.0 while mean finality falls: the p99 constraint is set by the latency tail, so path-jitter control (dedicated links, kernel bypass) buys more distance than lower median latency.

*Figure 13. Simulated p99 floor at zero network latency. Both BLS variants violate T before any propagation delay (Proposition L).*

### D.2 Post-Quantum Signatures

**Post-quantum signatures** (O5). Ed25519 and BLS fall to Shor's algorithm. Measured FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA, security reducing to hash-function properties alone), mean verify time t̄_v; n_max from Proposition L with k = 8, t_dissem = 0.046 ms, T = 1 ms; certificate = q signatures at n = 21:

| scheme | signature | verify mean / p99 | n_max (Prop. L) | certificate, n=21 |
|---|---|---|---|---|
| Ed25519 (reference) | 64 B | 0.063 / 0.099 ms | 151 | 1.1 KB |
| ML-DSA-44 | 2,420 B | 0.181 / 0.247 ms | 52 | 41 KB |
| ML-DSA-65 | 3,309 B | 0.299 / 0.602 ms | 31 | 56 KB |
| ML-DSA-87 | 4,627 B | 0.535 / 0.975 ms | 17 (< 21) | 79 KB |
| SLH-DSA-SHA2-128s | 7,856 B | 1.60 / 3.74 ms | 0 — one verify > T | 134 KB |
| SLH-DSA-SHA2-128f | 17,088 B | 4.27 / 4.52 ms | 0 — one verify > T | 290 KB |

A post-quantum 1 ms chain is feasible only with lattice signatures: ML-DSA-44 supports n ≤ 52 (bound; the service-time tail lowers it as in §6.4) at a 41 KB certificate, ≈37× Ed25519's. Hash-only SLH-DSA — the conservative choice, resting on the same assumptions as Corollary 13′ — cannot meet 1 ms at any n: a single verification exceeds T. Its ≈1.6–4.3 ms verify fits the two-chain slow path instead.

### D.3 Hashing Budget and Critical-Path Hashing

> **PROPOSITION P (hashing budget).** A batch of m operations needs 2m − 1 domain-separated hashes. With per-hash cost t_h on k cores, t_merkle ≈ (2m − 1)·t_h/k + ⌈log₂ m⌉·t_h. Leaf digests can be computed as operations arrive, leaving m − 1 internal hashes on the critical path.

| hash (native, 65-B input) | t_h | full tree m=4096, k=1 | k=8 | max m for t_merkle ≤ 0.1 ms, k=8 |
|---|---|---|---|---|
| SHA-256 (SHA-NI) | 0.231 µs | 1.89 ms | 0.24 ms | ≈1,730 |
| BLAKE2b | 0.365 µs | 2.99 ms | 0.38 ms | ≈1,095 |
| BLAKE2s | 0.467 µs | 3.83 ms | 0.48 ms | ≈855 |
| SHA3-256 | 0.551 µs | 4.51 ms | 0.57 ms | ≈725 |
| **SHA-384 (97-B input, specified)** | 0.398 µs | 3.26 ms | 0.41 ms | ≈1,005 |

OpenSSL 3 on a 2.1 GHz Xeon with SHA extensions. The 4,096-op batch of §6.2 does not fit a 1 ms slot single-threaded; at k = 8 it costs 24% of T with SHA-256 and 41% with SHA-384. SHA-256 is the fastest instantiation on SHA-NI hardware; SHA-384 is specified for its quantum margin (Proposition Q′) and made latency-neutral by streaming (Propositions R–R″). Batch size must scale with Δ_slot (Proposition O) and hashing cores together.

**Critical-path hashing.** Computing the root at batch close adds (m − 1)·t_h/k before the leader signs, and the cost compounds with withholding: at k = 8 the budget is 53.9 / 51.6 / 49.0 / 45.1 / 35.2 / 17.0 km for b = 0–5 (b = 5 loses the fast path, 21 − 5 < 17). Fig. 14 gives the full grid.

*Figure 14. Distance budget for p99 ≤ 1 ms over withholders b and Merkle critical-path cost; 24 binary searches, 15,000 slots per cell, simulated.*

### D.4 Arrival Order and Hashing Cores

> **PROPOSITION R′ (order-independent streaming).** Hash each node once all leaves beneath it have arrived, on k cores, list-scheduled by readiness. The root depends only on the leader's indices, not on arrival order; the post-arrival latency satisfies D_k ≥ max((⌊log₂ m⌋ + 1)·t_h, Q_k), where Q_k is the hashing backlog (in time) when the last operation lands; in every simulated case D_k lies within 1.3 µs of (⌊log₂ m⌋ + 1)·t_h + Q̂_k, with Q̂_k the bound of Proposition R″.

> **PROPOSITION R″ (backlog under random arrival order).** Let m leaves arrive i.i.d. uniform on [0, A]. A height-j node is released after A(1 − ε) iff one of its 2^j leaves arrives in the final window, so the expected work released there is N(ε)·t_h with N(ε) = Σ_{j=0}^{log₂ m} (m/2^j)·(1 − (1 − ε)^{2^j}). Then E[Q_k] ≥ sup_{ε∈(0,1]} [N(ε)·t_h/k − εA]⁺.

> *Proof.* Reich's formula for a k-server work-conserving queue gives Q_k ≥ sup_s (W(s, A] − k(A − s))/k with W(s, A] the work released in (s, A]; take s = A(1 − ε) and expectations, and use E[sup] ≥ sup E. Linearity over the m/2^j nodes at height j gives N(ε). □

| hashing cores k | load (2m−1)t_h/(kA) | in-order, mean | jitter 5 µs, p99 | random, mean | random, p99 | floor + R″ bound |
|---|---|---|---|---|---|---|
| 2 | 1.05 | 47.5 µs | 48.8 µs | 204 µs | 221 µs | 204.0 µs |
| 4 | 0.53 | 3.0 µs | 3.0 µs | 24.6 µs | 31.2 µs | 24.6 µs |
| 8 | 0.26 | 3.0 µs | 3.0 µs | 3.6 µs | 5.3 µs | 3.7 µs |
| 16 | 0.13 | 3.0 µs | 3.0 µs | 3.0 µs | 3.0 µs | 3.0 µs |

Event simulation, m = 4,096, arrivals over A = 0.9 ms, t_h = 0.231 µs, 150–300 batches per cell. The leader sees operations in index order by construction; a voter sees them in near-order (jitter ≪ A). k = 4 hashing cores meet the 3.0 µs floor for ordered arrival and k = 8 bound the worst case at 5.3 µs p99. The Proposition R″ bound plus the 3.0 µs floor matches the simulated mean within 0.3 µs in every row.

### D.5 Verification Cores

**Signature-verification cores** (streaming roots, n = 21, 8 seeds' baseline):

| verification cores | 1 | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|
| budget, b = 0 | infeasible (p99 1.30 ms at 0 km) | 39.7 km | 61.9 km | 62.6 km | 62.6 km |
| budget, b = 4 | infeasible | 37.8 km | 41.6 km | 41.6 km | 41.6 km |

Verification saturates at k = 4: beyond it the budget is set by propagation alone. One core cannot verify q = 17 votes (17 × 0.063 ms ≈ 1.07 ms) inside T. Reference validator: 4 verification + 16 hashing cores (SHA-384, Prop. Q′; 8 suffice for SHA-256).

*Figure 15. Left: distance budget vs signature-verification cores. Right: Merkle-root latency after the last operation vs hashing cores (log–log); simulated.*

### D.6 Geometry, Validator Count and Withholding

**Geometry.** The distances above put every pair at the same one-way median, the worst case for a given diameter. Random placement with pair medians d_ij/c_f plus a fixed per-hop NIC + switch latency c₀ (streaming roots, 4 cores, σ = 0.3, random leader and observer, 50 layouts per evaluation):

| placement | c₀ | max diameter | mean t_fin | vs equidistant | seeds |
|---|---|---|---|---|---|
| all pairs equidistant (Prop. F) | 0 | 62.5 ± 0.1 km | 0.89 ms | 1.00× | 8 |
| uniform on a circle | 0 | 78.1 ± 0.2 km | 0.80 ms | 1.25× | 5 |
| uniform in a disk | 0 | 102.6 ± 1.4 km | 0.74 ms | **1.64×** | 5 |
| uniform in a disk | 5 µs (kernel bypass) | 101.6 km | 0.75 ms | 1.63× | 2 |
| uniform in a disk | 50 µs (kernel TCP) | 90.7 km | 0.77 ms | 1.45× | 2 |

The q-th vote comes from the nearest ⌈0.8n⌉ validators, discounting the far tail of the distance distribution. Diameter falls ≈0.24 km per µs of c₀ (2, 10, 25 µs: 102.7, 100.0, 96.9 km); jitter σ moves the budget 2.7× over its range, so path-jitter control dominates stack latency.

**Validator count.** With k = 8 cores and equidistant pairs the budget is 63 / 59 / 29 km at n = 21 / 64 / 100 and n = 150 is infeasible: the service-time tail (p99 0.099 vs mean 0.063 ms) moves the Proposition L bound of 151 to between 100 and 150. Scaling k with n removes the limit (reference design below).

*Figure 16. Distance budget against validator count (8 cores). Verification queueing makes n=150 infeasible.*

**Adversarial withholding.** At the 62.6 km equidistant point, b = 2 / 4 / 5 / 6 silent validators raise p99 to 1.09 / 1.45 / 2.00 / 2.15 ms (10,000 slots each); b ≥ n/5 forces the two-round slow path at any distance. Distance budgets by b are in Fig. 14; safety is unaffected (Theorem A).

### D.7 Slot Clock, Pipelining and Bandwidth

**Slot clock and pipelining.** A transaction waits W ~ U(0, Δ_slot) for the next proposal, so t_e2e = W + t_fin and p99(t_e2e) ≥ 0.99·Δ_slot; at Δ_slot = 32 ms, simulated p99(t_e2e) = 32.6 ms. Sub-ms slots overlap: certificate j completes at c_j = jΔ + t_fin,j, possibly after c_{j+1}. Under in-order commit, slot j commits at C_j = max_{i≤j} c_i. For p99(t_e2e) ≤ 1 ms (30,000 slots per row):

| Δ_slot | in flight E[t_fin]/Δ | reordered c_{j+1} < c_j | distance, independent commit | distance, in-order commit |
|---|---|---|---|---|
| 32 ms (current) | ≈0.03 | 0% | infeasible | infeasible |
| 0.5 ms | 1.0 | 0.00% | 18.3 km | 18.4 km |
| 0.25 ms | 2.9 | 0.00% | 46.3 km | 46.5 km |
| 0.1 ms | 8.4 | 2.2–2.5% | 57.7 km | 57.8 km |

In-order commit costs nothing measurable (≤0.2 km, within Monte Carlo error): reordering is rare because t_fin has a tight tail relative to Δ. End-to-end 1 ms therefore needs Δ_slot ≤ 0.25 ms (≤46 km) with 3–8 certificates in flight; at Δ_slot = 0.25 ms the 576 KB coded batch needs ≈18 Gbps per validator. Safety with uncertified parents and recovery after splits are proved in §4.5 (Theorems A′, A″), which require the fast quorum and f < n/5 for pipelined finality.

> **PROPOSITION O (per-validator bandwidth).** All-to-all voting costs n(n−1) messages per slot; each validator sends and receives (n−1)·s_v bytes per slot, s_v = 104 B (64 B signature + 40 B header). Batch dissemination costs 1.5·B/Δ_slot. A timeout certificate is (n − f)·s_v bytes, once per failed slot.

| n | Δ_slot | messages / slot | vote traffic (each way) | batch traffic (576 KB coded) | TC size |
|---|---|---|---|---|---|
| 21 | 0.25 ms | 420 | 0.067 Gbps | 18.4 Gbps | 1.7 KB |
| 21 | 0.1 ms | 420 | 0.166 Gbps | 46.1 Gbps | 1.7 KB |
| 64 | 0.25 ms | 4,032 | 0.210 Gbps | 18.4 Gbps | 5.3 KB |
| 100 | 0.1 ms | 9,900 | 0.824 Gbps | 46.1 Gbps | 8.1 KB |

Votes stay below 1 Gbps for n ≤ 100; dissemination dominates by 20–50×. At Δ_slot = 0.1 ms a full 384 KB batch needs 46 Gbps, so per-slot batch size must scale with Δ_slot to hold the 100 GbE budget: B ≤ 100 Gbps · Δ_slot / (8·1.5) ≈ 833 KB·(Δ_slot / 0.1 ms). Recovery traffic (O(n²) timeout messages, ≤ 8.1 KB certificates) is negligible.

*Figure 17. Distance budget for p99(t_e2e) ≤ 1 ms against slot period (in-order commit).*

### D.8 Stake Concentration

**Stake concentration** (n=21, stake ∝ 1/rank^s; N_{1/3}, N_{1/5} = fewest validators exceeding 1/3 and 1/5 of stake):

| s | max share | N_{1/3} (safety) | N_{1/5} (fast path) | p99 @ 0.31 ms | distance |
|---|---|---|---|---|---|
| 0 (equal) | 4.8% | 8 | 5 | 0.991 ms | 63 km |
| 0.5 | 12.8% | 4 | 2 | 1.039 ms | 60 km |
| 1.0 | 27.4% | 2 | 1 | 1.164 ms | 52 km |
| 1.5 | 45.8% | 1 | 1 | 1.164 ms | 52 km |

Skew worsens latency as well as decentralization: quorums must wait for specific large validators, so p99 rises while N_{1/5} falls to 1 at s ≥ 1. A stake cap is a latency parameter (O24).

*Figure 18. Stake skew: decentralization (left) and distance budget (right).*

### D.9 Native Critical-Path Components

C, -O2, 4-vCPU host; libsodium Ed25519 and OpenSSL SHA-384 (low-level API). These pre-run Appendix C tests T2 and T4 on one machine; they measure CPU cost, not network latency.

| component | configuration | measured p50 | measured p99 | model |
|---|---|---|---|---|
| verify 17 of 21 votes | 1 thread | 0.953 ms | 1.711 ms | infeasible (D.5) |
| verify 17 of 21 votes | 2 threads | 0.500 ms | 0.848 ms | — |
| verify 17 of 21 votes | **4 threads** | 0.273 ms | **0.353 ms** | p99 0.339 ms (Prop. L sim.) |
| verify 14 of 21 votes (slow round) | 4 threads | 0.220 ms | 0.300 ms | — |
| streaming root tail, m = 4,096 | 1 thread, in order | 3.57 µs | 6.34 µs | ≤ 13 t_h = 3.6 µs |
| streaming root tail, m = 1,366 | 1 thread, in order | 2.07 µs | 4.43 µs | ≤ 11 t_h = 3.0 µs |
| whole streaming root, m = 4,096 | 1 thread | 2.22 ms | — | (2m − 1)·t_h = 2.25 ms |
| UDP one-way, 104-B vote, loopback | kernel, blocking recv | 13.4 µs | 32.6 µs (p99.9 114) | c₀ = 10–25 µs: 100–97 km |
| UDP one-way, 104-B vote, loopback | kernel, busy-poll | 2.5 µs | 6.0 µs (p99.9 19.5) | c₀ = 2–5 µs: ≈102 km |

5,000 trials (verification) and 3,000 batches (hashing); 0 verification failures. The verification p99 lies 4% above the simulated floor, validating the service-time model behind every distance budget. The whole-batch row confirms Proposition R (iv): one core cannot stream a 4,096-op batch inside a 1 ms slot, but a K = 3 proposer share (m = 1,366, 0.74 ms) fits on one core. The UDP rows bound the kernel share of c₀ (no NIC or wire): a busy-polling receive thread cuts median latency 5.4× and the p99.9 tail 5.8×, and the tail is what the p99 budget pays for (σ, Appendix D.1). The reference validator therefore dedicates one busy-polling core to receive. Recalibration: re-running the reference design with these native Ed25519 samples (median 0.053 ms, p99 0.120 ms, against PyNaCl's 0.063 / 0.099 ms) gives 81.3–82.2 km end-to-end (was 80.8), 50.7–50.8 km with four silent validators (was 50.8) and 102.1 km certificate-only (was 101.4): the lower median and heavier tail offset, and every headline distance moves by ≤ 1 km.

### D.10 State-Root Update: Native Measurement and Trie Arity

Complete binary SHA-384 trie of depth D = 20 (100 MB), leaf 0x06, node 0x07; m random keys per batch; dirty nodes rehashed level by level with OpenMP on a 4-vCPU host; 30 batches per row.

| m (keys per root) | hashes / op (pred.) | 1 thread | 2 threads | 4 threads | Prop. X prediction, 4 threads |
|---|---|---|---|---|---|
| 4,096 | 9.09 (9.11) | 13.5 ms | 6.8 ms | **3.36 ms** | 3.71 ms |
| 32,000 (1 M ops/s, E = 32 ms) | 6.15 (6.15) | 71.7 ms | 36.5 ms | **18.8 ms** | 19.6 ms |

Best of 30 batches; means are 4–22% higher on the shared host. An implementation hazard: OpenSSL 3's one-shot SHA384() resolves the algorithm per call — 0.667 µs per 97-byte hash and no thread scaling — while the low-level API costs 0.276 µs single-threaded and scales linearly. A state-root implementation must use the latter (or a pre-fetched EVP context).

| trie arity | SHA-384 blocks per node | internal nodes / op | blocks / op | membership proof |
|---|---|---|---|---|
| **2** | 1 | 7.15 | 8.15 | **1,152 B** |
| 4 | 2 | 3.33 | 7.65 (−6%) | 1,728 B |
| 16 | 7 | 1.41 | 10.90 (+34%) | 4,320 B |

D = 24, m = 128,000 (4 M ops/s, E = 32 ms). A 4-ary trie saves 6% of hashing at 1.5× the proof size; 16-ary loses on both because a node spans 7 blocks. NIMBUS keeps the binary trie.

### D.11 Fast-Path Robustness: Fallback Rate, Host Stalls, Quorum Slack

| b crashed | diameter, Δ_skip | fast quorum | slow-path fallback | timeout (TC) | instances |
|---|---|---|---|---|---|
| 0 | 50 km, 0.40 ms | 100.000% | 0.000% | 0 | 90,000 |
| 0 | 70 km, 0.55 ms | 100.000% | 0.000% | 0 | 90,000 |
| 2 | 50 km, 0.40 ms | 99.953% | 0.047% | 0 | 90,000 |
| 4 | 40 km, 0.40 ms | 98.737% | **1.263%** | 0 | 90,270 |

How often each (t, j) instance leaves the fast path, n = 21, K = 3, at the envelope's edge points. With b = 4, q = 17 equals the live count, so one vote landing on the other side of Δ_skip splits the instance; each crashed validator removes one unit of slack. No instance needed a timeout certificate in the model — it has network jitter but no host stalls, which P0-U shows are the other source of splits (Appendix E.3).

**Host stalls.** A stall meter (one pinned busy thread per core, all four cores loaded, recording every gap > 5 µs in the clock loop for 40 core-seconds) measured this cloud host at 1.7 stalls per core-ms, size p50 20 µs, p90 39 µs, p99 214 µs, p99.9 2.3 ms, max 13.6 ms — 5.8% of CPU time lost. Injected into the n = 21 model as a Poisson process on every validator's processing (rate λ_s, sizes resampled from the measurement):

| point (Δ_skip) | no stalls: ordering p99 / fallback | 0.1 × this host | 1 × this host |
|---|---|---|---|
| b = 0, 70 km (0.55 ms) | 0.913 ms / 0.000% | 0.916 ms / 0.000% | 0.933 ms / 0.000% |
| b = 2, 50 km (0.40 ms) | 0.969 ms / 0.047% | 0.971 ms / 0.078% | 0.985 ms / 0.110% |
| b = 4, 40 km (0.40 ms) | 0.981 ms / 1.263% | 0.998 ms / 1.454% | **1.014–1.015 ms** / 3.54–3.64% |
| b = 4, 35 km (0.35 ms) | — | — | 0.965 ms / 4.60% |

90,000 instances per cell; the b = 4, 40 km cell at full noise holds on two seeds. Stalls leave the b ≤ 2 envelope intact even at this VM's noise level, but at b = 4 — where q equals the live count and every stall on any live validator delays the quorum — they triple the fallback rate and pull the ordering edge from 40 to 35 km. p99.9 is more sensitive (1.14 ms at b = 0, 70 km). A host with ≤ 0.1× this stall rate (≤ 0.17 stalls per core-ms, typical of isolated cores with interrupt steering) keeps the published envelope; this is Appendix C test T12.

> **PROPOSITION Y (quorum slack).** With b validators crashed, the fast path has slack σ(n, b) = n − b − ⌈0.8n⌉: the fast quorum forms at the (σ + 1)-th slowest live vote. If each live vote independently misses the instance's deadline with probability p, the instance leaves the fast path with probability P_σ = Pr[Bin(n − b, p) > σ] ≈ C(n − b, σ + 1)·p^(σ+1). The largest b with σ ≥ s is ⌊0.2n⌋ − s, so each unit of slack at fixed b costs five validators.

> *Proof.* The fast quorum needs ⌈0.8n⌉ of the n − b live votes; it misses iff more than n − b − ⌈0.8n⌉ = σ of them are late. The binomial tail's leading term gives the approximation for small p. □

| n (q, cores k ≈ n/6) | σ at b = 4 | fallback, measured | P_σ, p fitted at n = 21 | ordering p99 at 40 km | ordering edge |
|---|---|---|---|---|---|
| 21 (17, 4) | 0 | 3.54–3.64% | 3.57% (fit) | 1.014–1.015 ms | 35 km |
| 26 (21, 5) | 1 | 0.12–0.17% | 0.10% | 0.993–0.995 ms | 40 km (45 km: 1.001) |
| 31 (25, 6) | 2 | 0.008% | 0.003% | 0.986 ms | **45 km** (50 km: 0.997–1.000, 3 seeds) |

b = 4 crashed, full host-stall noise (1×), K = 3, Δ_skip = 0.4 ms, 90,000 instances per cell; p = 0.0021 per vote from the n = 21 point. The binomial model predicts the fallback rate within 1.7× at σ = 1 and 3× at σ = 2 (stalls are not independent across a validator's votes). Committee size is therefore a robustness lever as well as a decentralization one: at a fixed tolerance of four crashes, n = 31 with six verification cores restores a 45 km ordering envelope on a noisy host (50 km sits on the 1 ms line), against 35 km at n = 21.

## Appendix E — Prototype Runs (§6.5)

### E.1 P0: Fast Path

| n (q) | slots | certificates | missing | conflicting digests | t_cert p50 | p90 | p99 |
|---|---|---|---|---|---|---|---|
| 4 (4) | 3,000 | 12,000 | 0 | 0 | 0.648 ms | 0.786 ms | 1.51 ms |
| 5 (4) | 3,000 | 15,000 | 0 | 0 | 0.703 ms | 0.916 ms | 2.59 ms |
| 7 (6) | 3,000 | 21,000 | 0 | 0 | 1.140 ms | 1.764 ms | 4.16 ms |

Loopback on one 4-vCPU host, kernel UDP with blocking receive. All n validators share four cores, so a slot costs ≈ n(n + 1) verifications on four cores instead of n + 1 on a dedicated validator's four: at n = 5 the host does 30 verifications (≥ 0.42 ms of CPU per core) where a dedicated node does 6. P0 therefore demonstrates correctness and a working code path, not the 1 ms network result; its p99 is scheduler contention. One bug found by P0 is now a protocol rule: a vote for an earlier slot must be routed to that slot's state, never allowed to reset the current slot's (the first build lost up to 0.7% of certificates this way).

### E.2 P0 as a Check on the Simulator

**P0 as a check on the simulator.** P0 was extended to hold each message until a due time drawn from the simulator's lognormal delay (median ow, σ = 0.3), and run at n = 3 (q = 3) so that each validator has a core. A discrete-event model of the same code — one single-server queue per validator, service times sampled from this host's native Ed25519 verify (mean 0.075 ms) and sign (0.028 ms) — predicts its certificate latency:

| one-way median ow | model p50 / p99 | P0, shared cores p50 / p99 | P0, pinned p50 / p99 | pinned − model, p50 |
|---|---|---|---|---|
| 0 | 0.325 / 0.447 ms | 0.485 / 0.771 ms | 0.447 / 0.705 ms | +0.122 ms |
| 0.1 ms | 0.501 / 0.627 ms | 0.556 / 2.300 ms | 0.614 / 1.020 ms | +0.113 ms |
| 0.2 ms | 0.710 / 0.932 ms | 0.766 / 2.207 ms | 0.841 / 1.078 ms | +0.131 ms |
| 0.3 ms | 0.936 / 1.287 ms | 1.022 / 2.569 ms | 1.037 / 1.471 ms | +0.101 ms |

2,000–3,000 slots per row, 0 conflicts. Two findings. (i) The model's median is low by a near-constant 0.10–0.13 ms. Instrumenting P0 locates it: crypto per certificate costs 418 µs in place against 328 µs from tight-loop microbenchmarks (1.27×), while waiting time matches the model. Cache-cold verification (8 MB flush between calls) reproduces it: 101–112 µs mean against 67–103 µs warm on this host. Service times must therefore be calibrated cache-cold. Re-running the reference design with native samples ×1.27 moves the headline by only 3–4 km — 77.2–78.9 km end-to-end (was 81.3–82.2), 47.7–48.4 km with four silent validators (was 50.8), 99.0 km certificate-only (was 102.1); six verification cores give 78.3 km, confirming that propagation, not verification, binds at k = 4. (ii) Unpinned threads inflate p99 2.2–3× through scheduler preemption; pinning each validator to a dedicated core cuts p99 2.1–2.3× and brings it to within 0.15–0.57 ms of the model. Core isolation is therefore a deployment requirement on the same footing as kernel-bypass networking. Headline distances in this paper use the in-place (×1.27) costs.

### E.3 P0-U: Skip Certificates

**P0-U: skip certificates executed.** P0 was extended with Proposition U: a live validator that has no proposal Δ_skip after slot start signs SKIP on r_⊥ = SHA-384(0x03 ∥ t ∥ j) — the registry's skip domain — and a slot resolves at q matching votes. n = 5, q = 4, validator 4 crashed (it leads every fifth slot), four live validators pinned to four cores, 2,500 slots per row:

| Δ_skip | live-leader certs p50 / p99 | crashed-leader skip certs p50 / p99 | skip p50 − Δ_skip | spurious skips | unresolved (split) | conflicts |
|---|---|---|---|---|---|---|
| 0.4 ms | 0.673 / 1.245 ms | 0.913 / 1.664 ms | 0.513 ms | 8 / 7,972 | 20 / 10,000 | 0 |
| 0.6 ms | 0.609 / 1.289 ms | 1.072 / 2.826 ms | 0.472 ms | 8 / 7,960 | 32 / 10,000 | 0 |
| 1.0 ms | 0.654 / 1.567 ms | 1.509 / 2.526 ms | 0.509 ms | 8 / 7,964 | 28 / 10,000 | 0 |

Every crashed-leader slot (2,000 per row) resolved by skip certificate, and no slot resolved to both outcomes at any two validators. Skip resolution costs Δ_skip + 0.47–0.51 ms, against Proposition U's Δ_skip + t_s + t_hop + q·t̄_v = Δ_skip + 0.33 ms at microbenchmark and + 0.42 ms at in-place (×1.27) costs; the remainder is polling and scheduling on a shared host. 0.2–0.3% of validator-slots end in a split vote (one validator's proposal delayed past Δ_skip by a scheduler stall) that reaches neither fast quorum; these are exactly the cases a fallback must resolve. A second protocol rule came from P0-U, the dual of the first: a message for a later slot must advance the validator's slot state rather than be discarded (the first build left 5% of validator-slots unresolved this way).

### E.4 P0-TC: Timeout-Certificate Fallback

**P0-TC: the fallback executed.** Split votes are resolved by the timeout certificates of Rule V+ (Theorem A″), not by a new mechanism. At Δ_to after slot start an unresolved validator signs a TIMEOUT statement over Hκ(0x08 ∥ t ∥ j ∥ its vote) and broadcasts it; a resolved validator answers the first TIMEOUT it sees with its own. On t = n − f valid statements the slot's anchor is the reported proposal digest with the most reports if it has ≥ τ = t − f − (n − q), else SKIP; reports are counted per digest, as Theorem A″ defines the anchor. The anchor is what the next proposal extends (Rule V+): a TC-anchored proposal is committed when the next certificate forms, one slot later — a TC is not itself a finality certificate. n = 5 (q = 4, t = 4, τ = 2), 2,500 slots per row, validators pinned:

| crashed | Δ_skip / Δ_to | fast proposal certs | fast skip certs | anchored by TC (P / skip) | TC p50 / p99 | unresolved | conflicts |
|---|---|---|---|---|---|---|---|
| 1 | 0.40 / 1.50 ms | 7,964 | 2,000 | 32 / 4 | 2.02 / 3.43 ms | 0 | 0 |
| 1 | 0.60 / 1.50 ms | 7,984 | 2,000 | 16 / 0 | 2.03 / 3.52 ms | 0 | 0 |
| 1 | 0.20 / 1.50 ms | 7,888 | 2,008 | 96 / 8 | 2.05 / 20.1 ms | 0 | 0 |
| 1 | 0.25 / 1.50 ms | 7,896 | 2,012 | 92 / 0 | 2.00 / 9.25 ms | 0 | 0 |
| 1 | 0.30 / 1.05 ms | 7,668 | 2,000 | 328 / 4 | 1.59 / 8.10 ms | 0 | 0 |
| 0 (5 on 4 cores) | 0.25 / 1.05 ms | 11,730 | 20 | 750 / 0 | 1.61 / 8.45 ms | 0 | 0 |
| 0 (5 on 4 cores) | 0.40 / 1.05 ms | 12,315 | 15 | 170 / 0 | 2.13 / 7.63 ms | 0 | 0 |

75,000 validator-slot outcomes, 1,500 through the fallback, 0 unresolved, 0 slots certified or anchored differently at two validators; a re-run of three rows after switching to per-digest counting (32,500 outcomes, 792 TC anchors) gave the same result. Short Δ_skip and an oversubscribed core were used deliberately to force splits. A TC anchor forms at ≈ Δ_to + 0.5 ms (median) and commits one slot later; its p99 (8–20 ms) is scheduler-bound on the shared host, so the fallback is a liveness mechanism, not part of the 1 ms tail. How often it is needed at n = 21 is measured in §6.4 (Proposition U): 0.000% / 0.047% / 1.263% of proposer instances at 0 / 2 / 4 crashed validators. Scope: at n = 5, f = 1 the condition 2q > n + 3f of Theorem A″ holds only with equality (8 = 8), so these runs exercise crash faults, for which the τ rule is sufficient; Byzantine safety of the same rule is proved for n = 21, q = 17, f = 4 (34 > 33).
