# nimbus-core v0.18

Twelve Rust crates for the NIMBUS DEX stack (whitepaper §3.1, §4.1, §6.4, §6.6; hash-input layouts in Appendix B,
Lemma 9″). Local development only. See AUDIT.md.

| crate | what it does | tests |
|---|---|---|
| `nimbus-replica` | Authenticated TCP transport for journal replication: operator-authenticated shipments, replica-authenticated acknowledgements and hello (domain 0x11; Ed25519 or HMAC-SHA384 per link), many batches in flight, `ReplicaServer` + `TcpReplica` (a `ReplicaStream`); **polled I/O: `TcpReplica::into_poll` + `attach_polled_windowed` + `serve_one_spinning` — no thread sleeps on the replication path** | byte-identical replicas and failover; forged shipment, altered or forged acknowledgement, wrong secret or index refused; silent replica dropped by timeout or in-flight cap; a refusing replica fails the quorum promptly; all in both I/O modes |
| `nimbus-bridge` | **Certifier**: a validator's journal replica that re-executes every slot (`Replayer`) and co-signs only operator-signed checkpoints it reproduces, at most one per slot across restarts; bounded memory with `open_retaining(.., W)` (keeps W slots, durable never-decreasing floor, compacted signing log); **restart from a snapshot (`set_snapshot_every(K)`): re-executes only the journal after the newest snapshot, falls back to full replay if snapshot or journal do not match**; `certify_with` builds the bridge's certificate. Bridge-side settlement: pays withdrawals and refunds engine-rejected deposits only against receipt proofs under operator-signed checkpoints, each receipt once (fsynced settled set); refuses a second signed checkpoint for a slot as equivocation; **`open_certified` also requires ≥ q validator co-signatures on the checkpoint (2n < 3q)** | pay/refund once across restarts; inflated, redirected and foreign receipts refused; operator-fabricated checkpoint refused for a settled slot and, when certified, for an unseen slot; short, repeated-signer, unknown and wrong-slot certificates refused; retention window bounded over 200 slots, pruned slots refused also after the journal is replaced by a shorter history, retained signing records survive compaction and restart; resumes at its newest snapshot with the same derivations and signatures and keeps replicating; damaged snapshot or substituted journal → full replay, equivocation still refused |
| `nimbus-sig` | The single Ed25519 rule for everything: `CheckedKey` (decodes, canonical, not small-order) and ZIP-215 verification, under which batch and single verification agree; `verify_all` batches by key on all cores and bisects failures; `verify_all_with(items, 1)` is the latency mode; **`SpinPool`: never-sleeping verification workers for sub-millisecond slots** (8 signatures: 155–173 µs p50 vs 434–489 µs on rayon here) | single = batch for random mixes incl. key-holder-crafted torsion signatures; reproduces the old rule's batch/single disagreement; finds exactly the bad signatures in 6 adversarial patterns |
| `nimbus-hash` | Domain-separated SHA-384; RFC 6962 Merkle roots (reference, streaming, parallel); audit paths; `MerkleTree` with O(log n) paths | streaming = reference = parallel; exactly 2m − 1 hashes; depth-confusion blocked; tree paths = reference paths |
| `nimbus-match` | Price-time-priority book, integer ticks/lots, checked u128 notional, full-lock admission, maker-price fills with refund, self-trade prevention, O(1) cancel, supply cap, deterministic state hash, parallel markets; **exact integer fees** (maker/taker bps, ⌈n·b/10⁴⌉ per side per fill, collector account, fee reserve L(p, r) that provably covers every fill; **maker rebates** ⌊n·ρ/10⁴⌋ paid out of the taker fee, ρ ≤ taker rate, maker rate 0); **fill-or-kill** (fills in full or is refused, state untouched) and **post-only** (refused if it would take, so it only ever makes) | property tests; differential test against a naive reference engine (account totals, locks re-derived from the book) at normal and extreme magnitudes under six fee schedules, two with rebates, with all four order types; hand-worked fee, rebate, fill-or-kill and post-only examples |
| `nimbus-order` | Signed **orders** (0x09), **account actions** — cancel, withdraw (0x0F), **bridge operations** — deposit, register (0x10); the journal `Entry` format; admission (keys, expiry, lifetime, strict shared nonces, **k-of-m bridge quorum**, one-time bridge references pruned after their expiry, **time in force GTC / IOC / FOK / post-only**, **per-slot deposit caps**); parallel batch `verify_entries` | batch = single admission; actions share nonces; bridge references apply once; same-slot registration then trading; cross-domain signatures refused; bridge quorum, caps and expiry; bit-flip fuzzing of all three message types; parser fuzzing |
| `nimbus-pipeline` | Slot pipeline: batch verification on all cores → ordered admission → **journal ∥ matching** (one fsync per slot, concurrent with matching) → receipts for every change (fills, cancels, expiries, deposits, withdrawals, registrations), each with the account's **post-trade balance**, and a **maker receipt for every fill** → signed checkpoint; **quorum journal replication** — blocking (`attach_replicas(set, need)`: acknowledge a slot only when `need` replicas hold it durably, shipped in parallel with the local fsync) or **windowed** (`attach_replicas_windowed(set, need, depth)` + `submit_slot` / `drain`: keep committing, release results in slot order once replicated); cross-slot pipelining (`process_slots`: verify slot s+1 while slot s commits); throughput or latency batching (`Config::min_batch`); expiry-only slots journaled as ticks; recovery by replay with checkpoint verification, **resumed from a snapshot** (`set_snapshot_every(K)`: encoded at slot end, sealed and written by a background `SnapshotWriter`; or a **`SnapshotFollower`** that re-executes the journal read-only off the engine's path); replay-state snapshots (`Replayer::snapshot` / `restore`, domain 0x12: books, balances, next order ids, supply, keys, nonces, references, deposit caps, expiries) | pipeline = independent sequential reference every slot on mixed traffic; receipt proofs; recovery; torn checkpoints; end-truncation; divergence; cancels, withdrawals, ticks; bridge quorum, caps and balances; latency mode = throughput mode; pipelined = slot by slot; every maker receipt checked; replica failover reproduces the signed checkpoint; replication quorum enforced; windowed = blocking results, in order, durable on the quorum at release; spin pool = throughput mode; hash-input vectors checked against the whitepaper's table; a snapshot at every cut point of a 40-slot mixed run resumes to the uninterrupted checkpoints; the engine resumes from its own or a follower's snapshot with the state of full replay and identical later results; damaged snapshot, unstored agent checkpoint, records cut after the snapshot → fallback or reported as without snapshots |
| `nimbus-journal` | Hash-chained WAL of typed entries (variable-length records, 207 B per order, domain 0x0B), group commit with durable watermark, anchored open, crash recovery, tamper detection; **`replicate`: a replica verifies shipped records against its own chain before writing them** | crash at any byte; any modified/removed/swapped record; anchors; **`open_from`: resume at a snapshot's anchor reading only the suffix** (= `open`'s suffix; replaced or cut file refused); `read_from`: the same, read-only, for a follower; batch = single appends; replica byte-identical to primary, altered/cut/gapped/replayed batches refused |
| `nimbus-sdk` | Agent risk policy, rate limiter, exact pre-trade simulation | policy bounds; preview = execution |
| `nimbus-signer` | Key-isolating signer: orders (feed-priced, fail closed on a stale feed) and **cancels** (allowed on a stale feed, own rate bucket); **no withdrawal path**; feed socket; persisted feed state | 10 end-to-end tests incl. cancel on a stale feed and refusal of withdrawal requests |
| `nimbus-feed` | k-of-m quorum attestations (0x0A), freshness, monotonic slots, conflict detection; ZIP-215 batch | forgery, quorum, staleness, regression, conflict, weak key, cross-domain, bit-flip, parser fuzz |
| `nimbus-lightclient` | Finality-proof verifier: header, inclusion path, ⌈0.8n⌉ distinct validators, ZIP-215 batch | valid proofs; 3,000 mutated proofs rejected; weak validator key refused |

## Measured on this 4-core VM (`./build_and_test.sh`)
| path | result |
|---|---|
| end to end — signed bytes → verified → admitted → journaled with fsync → matched → receipted → checkpointed; 90 % orders, 5 % cancels, 3 % withdrawals, 2 % deposits | **150,000–183,000 entries/s on 4 threads pipelined** (153,000–173,000 slot by slot; v0.12–v0.14 runs; with 10 / 5 bps fees: same range); sequential single-verification baseline 17,700–18,300/s; state identical to the baseline. Measured on a faster VM than earlier rounds (the v0.11 code there: 152,000–171,000) |
| with 2 journal replicas, both required | 127,000–141,000 entries/s pipelined (replicas on the same virtual disk here: three fsyncs per slot) |
| where the time goes (4 threads) | signature batches 61–64 %, journal ∥ matching 33–36 % (journal + fsync 29–32 %) |
| replication over loopback TCP (`tcp-bench`, 2 replicas both required, 1 ms slots) | sleeping threads add ≈ 0.9–1.2 ms at p50 (HMAC / Ed25519); **polled I/O adds ≈ 0.11 ms**; 1 replica at 0.5 ms slots: polled release 0.24 ms p50, same as no replica |
| replication latency (`repl-bench`, 0.5 ms slots, emulated link) | blocking falls behind at a ≈ 190 µs round trip; windowed keeps up to ≈ 930 µs with median release ≈ engine time + round trip |
| signature verification | `sig-bench`: single 60–65 µs; batched 17.4 µs CPU (4.4 µs wall on 4 threads); all-invalid flood 1.4–1.5× single; per-batch-size sweep 1–4,096 |
| receipt proof for an agent | 15 hashes; build ≈ 1 µs; agent-side check 75–117 µs (mostly the checkpoint signature) |
| acknowledgement latency | this VM's group commit: p50 0.65 ms, p99 1.8 ms — too slow for 1 ms; whitepaper §6.6: p99 ≤ 1 ms needs 0.25 ms slots, a ≤ 50 µs durable flush, `min_batch = 1`, a spin pool on reserved cores, and replicas within ≈ 10–16 km (≈ 23–43 km with windowed replication) |
| matching engine | 195 ns/op single market; 8.4 M ops/s across 16 markets; per order: IOC 212–233 ns, fill-or-kill 277–385 ns, refused post-only 46–56 ns |
| engine restart (`recovery-bench`, 600,000 orders, 8.7 MB state) | from genesis 4,485–4,623 ms; from a snapshot 113–115 ms; a snapshot costs the engine 12.1–12.5 ms of encoding (1.39 ms/MB), or nothing with a follower (which costs +27 % slot p50 when it shares the engine's 4 cores) |
| certifier restart (`certify-bench`, 200,000 orders) | replay from genesis 1,615–1,726 ms; 1.04 MB snapshot written in 5.4–6.9 ms; resume from it 16.6–16.7 ms |
| certifier memory (`certify-mem`) | 472 B per slot without a window (≈ 160 GB/day at 0.25 ms slots); with a 1,024-slot window 3.96 → 4.06 MB over 400,000 slots |

## Requirements
Rust 1.88+ (`curl https://sh.rustup.rs -sSf | sh`). No C toolchain or system libraries needed.

## Build, test, benchmark
    ./build_and_test.sh                                   # build, all tests (count: `python3 ../scripts/count_tests.py`), benchmarks, fmt, clippy, cargo audit
    NIMBUS_NATIVE=1 ./build_and_test.sh                   # same, compiled for this CPU (target-cpu=native): pipelined 159–170 × 10³ entries/s vs 150–159 × 10³ default (+8% mean; slot by slot +5%), three interleaved runs
    PROPTEST_CASES=20000 PIPELINE_SLOTS=400 cargo test --release    # stress run
    ./target/release/sig-bench                            # verification cost, incl. invalid-signature floods and small-slot dispatch
    ./target/release/repl-bench                           # blocking vs windowed replication behind an emulated link
    ./target/release/tcp-bench                            # windowed replication over loopback TCP, Ed25519 vs HMAC links
    ./target/release/certify-bench                        # certifier re-execution rate, certify cost, snapshot size / write / resume
    ./target/release/recovery-bench                       # engine restart from genesis vs snapshot; slot time with snapshots (REC_FOLLOW=1: follower)
    ./target/release/certify-mem                          # certifier memory per slot, unbounded vs retaining (Linux)
    TIF_SPLIT=1 ./target/release/match-bench              # cost of IOC vs fill-or-kill vs post-only orders

## The engine pipeline
    let genesis = Genesis { accounts, deposits, bridge: bridge_public_keys, bridge_threshold: 2,
                            deposit_cap: Some((base_cap, quote_cap)) };
    let (mut p, report) = Pipeline::open(dir, Config { markets: 16, max_life: 1_000, fsync: true, min_batch: 16 },
                                         &genesis, operator_key, Some(&checkpoint_from_an_agent))?;
    let r = p.process_slot(slot, &submissions)?;          // Entry bytes: orders, actions, bridge ops
    // or: let rs = p.process_slots(&[(slot, &subs_a), (slot + 1, &subs_b)])?;  // verify s+1 while s commits
    for (i, d) in r.decisions.iter().enumerate() {
        match d {
            Ok(k) => reply(i, r.proof(*k)),               // receipt + Merkle path + signed checkpoint
            Err(why) => refuse(i, why),                   // refused entries consume no nonce or reference
        }
    }

Replication, latency mode and certified settlement:

    p.use_spin_pool(3);                                    // never-sleeping verification workers (reserve the cores)
    p.attach_replicas(vec![Box::new(replica_journal) /* or any transport implementing Replica */], 1)?;
    // or windowed: p.attach_replicas_windowed(set, need, 64)?; then p.submit_slot(slot, &subs)? / p.drain()?
    // over TCP: let r = TcpReplica::connect(addr, Auth::Mac(link_secret), id)?;
    //           p.attach_streams_windowed(vec![Box::new(r)], 1, WindowConfig { depth: 64, ack_timeout, max_inflight: 1024 })?;
    //   replica host: ReplicaServer::new(journal, Auth::Mac(link_secret), id)?.serve_one(&listener)?;
    // latency mode, no sleeping threads: p.attach_polled_windowed(vec![Box::new(r.into_poll()?)], 1,
    //   WindowConfig { spin: true, ..WindowConfig::new(64) })?;  replica host: .serve_one_spinning(&listener)?
    let bridge = Settlement::open_certified(path, operator_pk, Validators::new(&validator_pks, quorum)?)?;
    bridge.pay_certified(&proof, &Certificate::sign(&proof.checkpoint, &[(0, &v0), (1, &v1), /* ≥ quorum */]))?;

Entries: `Entry::Order(SignedOrder::sign(intent, &key))`, `Entry::Action(SignedAction::sign(Action { kind:
ActionKind::Cancel { order_id }, .. }, &key))`, `Entry::Bridge(SignedBridge::sign(BridgeOp { kind:
BridgeKind::Deposit { .. }, reference, expiry_slot }, &[(0, &bridge_key_0), (2, &bridge_key_2)]))`; submit `entry.to_bytes()`. An agent checks any receipt
offline with `ReceiptProof::verify(&operator_public_key)` and keeps the checkpoint.

## Running the signer
    ./target/release/nimbus-signer --gen-key agent.key            # prints the public key; file is chmod 600
    ./target/release/nimbus-signer --key agent.key --acct 7 --policy policy.json --feed feed.json \
        --socket /run/nimbus/agent7.sock --feed-socket /run/nimbus/feed7.sock --state /var/lib/nimbus/feed7.json

Agent requests, one JSON object per line on `--socket`:

    {"market":1,"side":"bid","price":1000,"qty":5,"tif":"gtc","expiry_slot":30}      # tif: gtc | ioc | fok | post_only
    {"cancel":{"market":1,"order_id":42}}

Responses: `{"ok":{"entry_hex":"…","nonce":N}}` (submit the entry to the engine) or `{"err":{"reason":"…"}}`. There
is deliberately no withdrawal request. The feed relay writes one hex attestation per line to `--feed-socket`.
`policy.json` and `feed.json` are unchanged from v0.4 (see AUDIT.md for the fields).

## Not included
The validator node (networking, consensus, storage) and the validators'
checkpoint re-derivation service are not part of this package.
