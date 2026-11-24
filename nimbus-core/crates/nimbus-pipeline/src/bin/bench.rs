//! End-to-end throughput: signed entry bytes in → verified, admitted, journaled (fsync per slot), matched, receipted
//! and checkpointed. Workload: 90 % orders, 5 % signed cancels of resting orders, 3 % withdrawals, 2 % bridge
//! deposits. Compares a sequential baseline (single verification, one thread, journal then match) with the pipeline
//! (ZIP-215 batch verification on all cores, journal ∥ matching) at 1, 2 and 4 threads.
//! Env: PIPELINE_ORDERS (default 400000), PIPELINE_SLOT (entries per slot, default 20000), PIPELINE_FEE_BPS (taker
//! rate; maker = taker / 2; default 0 = no fees).
use ed25519_dalek::SigningKey;
use nimbus_journal::Journal;
use nimbus_match::{Exchange, Op, Outcome, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::prelude::*;
use std::time::Instant;

const MARKETS: u32 = 16;
const ACCOUNTS: u32 = 4096;

fn env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

enum Plan {
    Order(Intent),
    Action(Action),
    Deposit(BridgeOp),
}

/// Fee schedule for the run: taker PIPELINE_FEE_BPS, maker half of it, collected by an account that does not trade.
fn fees_from_env() -> nimbus_match::Fees {
    let t = env("PIPELINE_FEE_BPS", 0) as u16;
    nimbus_match::Fees {
        maker_bps: t / 2,
        taker_bps: t,
        collector: u32::MAX,
        maker_rebate_bps: 0,
    }
}

fn main() {
    let total = env("PIPELINE_ORDERS", 400_000);
    let per_slot = env("PIPELINE_SLOT", 20_000);
    let mut rng = StdRng::seed_from_u64(42);
    let keys: Vec<SigningKey> = (0..ACCOUNTS)
        .map(|_| SigningKey::from_bytes(&rng.gen()))
        .collect();
    let bridge: Vec<SigningKey> = (77..80u8)
        .map(|b| SigningKey::from_bytes(&[b; 32]))
        .collect();
    let genesis = Genesis {
        accounts: (0..ACCOUNTS)
            .map(|a| (a, keys[a as usize].verifying_key()))
            .collect(),
        deposits: (0..MARKETS)
            .flat_map(|m| (0..ACCOUNTS).map(move |a| (m, a, 1u128 << 40, 1u128 << 60)))
            .collect(),
        bridge: bridge.iter().map(|k| k.verifying_key()).collect(),
        bridge_threshold: 2,
        deposit_cap: None,
        fees: fees_from_env(),
    };

    // Plan the workload. Cancels name order ids the market will have assigned (ids are per market: 1, 2, 3, …) and
    // are signed by the order's owner, so they hit resting or already-filled orders — as a real agent's would.
    let mut nonces = vec![0u64; ACCOUNTS as usize];
    let mut owner: Vec<Vec<u32>> = vec![Vec::new(); MARKETS as usize];
    let plans: Vec<(u64, Plan)> = (0..total)
        .map(|i| {
            let slot = 1 + (i / per_slot) as u64;
            let m = rng.gen_range(0..MARKETS);
            let placed = owner[m as usize].len() as u64;
            let roll = rng.gen_range(0..100);
            let mut take = |a: u32| {
                nonces[a as usize] += 1;
                nonces[a as usize] - 1
            };
            if roll < 5 && placed > 10 {
                let id = rng.gen_range(placed.saturating_sub(2_000).max(1)..=placed);
                let a = owner[m as usize][id as usize - 1];
                let kind = ActionKind::Cancel { order_id: id };
                return (
                    slot,
                    Plan::Action(Action {
                        market: m,
                        acct: a,
                        nonce: take(a),
                        expiry_slot: slot + 10,
                        kind,
                    }),
                );
            }
            let a = rng.gen_range(0..ACCOUNTS);
            if roll < 8 {
                let kind = ActionKind::Withdraw {
                    base: 1,
                    quote: 1_000,
                };
                return (
                    slot,
                    Plan::Action(Action {
                        market: m,
                        acct: a,
                        nonce: take(a),
                        expiry_slot: slot + 10,
                        kind,
                    }),
                );
            }
            if roll < 10 {
                let mut r = [0u8; 32];
                r[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let kind = BridgeKind::Deposit {
                    market: m,
                    acct: a,
                    base: 10,
                    quote: 10_000,
                };
                return (
                    slot,
                    Plan::Deposit(BridgeOp {
                        reference: r,
                        expiry_slot: slot + 10,
                        kind,
                    }),
                );
            }
            owner[m as usize].push(a);
            (
                slot,
                Plan::Order(Intent {
                    market: m,
                    acct: a,
                    side: if rng.gen_bool(0.5) {
                        Side::Bid
                    } else {
                        Side::Ask
                    },
                    price: rng.gen_range(990..1011),
                    qty: rng.gen_range(1..50),
                    tif: if rng.gen_bool(0.2) {
                        Tif::Ioc
                    } else {
                        Tif::Gtc
                    },
                    nonce: take(a),
                    expiry_slot: slot + rng.gen_range(0..20),
                }),
            )
        })
        .collect();
    let t = Instant::now();
    let wire: Vec<Vec<u8>> = plans
        .par_iter()
        .map(|(_, p)| {
            match p {
                Plan::Order(i) => Entry::Order(SignedOrder::sign(*i, &keys[i.acct as usize])),
                Plan::Action(a) => Entry::Action(SignedAction::sign(*a, &keys[a.acct as usize])),
                Plan::Deposit(b) => {
                    Entry::Bridge(SignedBridge::sign(*b, &[(0, &bridge[0]), (2, &bridge[2])]))
                }
            }
            .to_bytes()
        })
        .collect();
    println!(
        "prepared {total} signed entries ({ACCOUNTS} accounts, {MARKETS} markets, {per_slot}/slot) in {:.2} s",
        t.elapsed().as_secs_f64()
    );
    let slots: Vec<(u64, &[Vec<u8>])> = wire
        .chunks(per_slot)
        .enumerate()
        .map(|(i, c)| (1 + i as u64, c))
        .collect();
    let dir = std::env::temp_dir().join(format!("pipeline-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Baseline: same semantics, sequential — single signature verification, journal + fsync, then matching.
    let base_hash = {
        let mut adm = Admission::new();
        adm.set_max_life(1_000);
        for (a, k) in &genesis.accounts {
            adm.register(*a, *k).unwrap();
        }
        adm.set_bridge(
            &bridge
                .iter()
                .map(|k| k.verifying_key().to_bytes())
                .collect::<Vec<_>>(),
            2,
        )
        .unwrap();
        let mut ex = Exchange::new(MARKETS as usize);
        ex.set_fees(fees_from_env()).unwrap();
        for &(m, a, b, q) in &genesis.deposits {
            ex.markets[m as usize].apply(&Op::Deposit {
                acct: a,
                base: b,
                quote: q,
            });
        }
        let (mut j, _) = Journal::open(&dir.join("baseline.bin"), usize::MAX).unwrap();
        let mut expiries = std::collections::BTreeMap::new();
        let t = Instant::now();
        for (slot, subs) in &slots {
            while let Some((&(e, m, id), &acct)) = expiries.first_key_value() {
                if e >= *slot {
                    break;
                }
                expiries.pop_first();
                ex.markets[m as usize].apply(&Op::Cancel { acct, id });
            }
            let mut admitted = Vec::with_capacity(subs.len());
            for b in subs.iter() {
                let e = Entry::from_bytes(b).unwrap();
                let items = adm.items_for(&e).unwrap();
                let v = verify_entry(e, &items).unwrap();
                let eff = adm.admit_verified(&v, *slot).unwrap();
                admitted.push((v.into_inner(), eff));
            }
            let refs: Vec<&Entry> = admitted.iter().map(|(e, _)| e).collect();
            j.append_batch(*slot, &refs).unwrap();
            j.sync().unwrap();
            for (e, eff) in &admitted {
                if let Effect::Market { market, op } = eff {
                    let out = ex.markets[*market as usize].apply(op);
                    if let (Entry::Order(o), Outcome::Placed { id, resting, .. }) = (e, out) {
                        if resting > 0 && o.intent.tif.rests() {
                            expiries
                                .insert((o.intent.expiry_slot, o.intent.market, id), o.intent.acct);
                        }
                    }
                }
            }
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "baseline  (sequential, single verify, 1 thread):  {:>9.0} entries/s  ({:.2} s)",
            total as f64 / dt,
            dt
        );
        ex.state_hash()
    };

    for threads in [1usize, 2, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let d = dir.join(format!("p{threads}"));
        let (hash, tim, dt, stats, last) = pool.install(|| {
            let cfg = Config {
                markets: MARKETS,
                max_life: 1_000,
                fsync: true,
                min_batch: 16,
            };
            let (mut p, _) =
                Pipeline::open(&d, cfg, &genesis, SigningKey::from_bytes(&[9; 32]), None).unwrap();
            let mut tim = Timings::default();
            let mut stats = [0usize; 4]; // fills, cancels, withdrawals, deposits
            let mut last = None;
            let t = Instant::now();
            for (slot, subs) in &slots {
                let r = p.process_slot(*slot, subs).unwrap();
                assert!(
                    r.decisions.iter().all(|d| d.is_ok()),
                    "every planned entry is admissible"
                );
                for rc in &r.receipts {
                    match &rc.status {
                        Status::Executed { fills, .. } => stats[0] += fills.len(),
                        Status::Cancelled { .. } => stats[1] += 1,
                        Status::Withdrawn { .. } => stats[2] += 1,
                        Status::Deposited { .. } => stats[3] += 1,
                        _ => {}
                    }
                }
                tim.add(&r.timings);
                last = Some(r);
            }
            (
                p.exchange().state_hash(),
                tim,
                t.elapsed().as_secs_f64(),
                stats,
                last.unwrap(),
            )
        });
        assert_eq!(
            hash, base_hash,
            "pipeline state differs from the sequential baseline"
        );
        let pct = |d: std::time::Duration| 100.0 * d.as_secs_f64() / tim.total().as_secs_f64();
        println!(
            "pipeline  ({threads} thread{}): {:>9.0} entries/s  ({:.2} s) | verify {:.0}% admit {:.0}% journal∥match {:.0}% (journal {:.0}%, match {:.0}%) ckpt {:.1}% expire {:.1}%",
            if threads == 1 { " " } else { "s" },
            total as f64 / dt,
            dt,
            pct(tim.verify),
            pct(tim.admit),
            pct(tim.commit),
            pct(tim.journal),
            pct(tim.matching),
            pct(tim.checkpoint),
            pct(tim.expire),
        );
        if threads == 4 {
            println!(
                "           state identical to baseline ({}…); {} fills, {} cancels (incl. expiries), {} withdrawals, {} deposits",
                &hex(&hash)[..16],
                stats[0],
                stats[1],
                stats[2],
                stats[3]
            );
            let n = last.receipts.len();
            let t = Instant::now();
            let proofs: Vec<ReceiptProof> = (0..n).map(|i| last.proof(i).unwrap()).collect();
            let build = t.elapsed().as_secs_f64() / n as f64;
            let pk = SigningKey::from_bytes(&[9; 32]).verifying_key();
            let t = Instant::now();
            let k = n.min(2_000);
            assert_eq!(proofs.iter().take(k).filter(|p| p.verify(&pk)).count(), k);
            let check = t.elapsed().as_secs_f64() / k as f64;
            println!(
                "           receipt proof ({n} receipts/slot, {} hashes/path): build {:.2} µs, agent check {:.1} µs",
                proofs[0].path.len(),
                build * 1e6,
                check * 1e6
            );
        }
    }
    // Cross-slot pipelining: verification of slot s+1 overlaps the commit of slot s (4 threads), without replicas and
    // with two local journal replicas that must both fsync every slot (same disk here: an upper bound on the cost).
    for replicas in [0usize, 2] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let d = dir.join(format!("piped{replicas}"));
        let (hash, dt) = pool.install(|| {
            let cfg = Config {
                markets: MARKETS,
                max_life: 1_000,
                fsync: true,
                min_batch: 16,
            };
            let (mut p, _) =
                Pipeline::open(&d, cfg, &genesis, SigningKey::from_bytes(&[9; 32]), None).unwrap();
            let set: Vec<Box<dyn Replica>> = (0..replicas)
                .map(|i| {
                    let path = d.join(format!("replica{i}.bin"));
                    Box::new(nimbus_journal::Journal::open(&path, usize::MAX).unwrap().0)
                        as Box<dyn Replica>
                })
                .collect();
            p.attach_replicas(set, replicas).unwrap();
            let t = Instant::now();
            let rs = p.process_slots(&slots).unwrap();
            assert!(rs.iter().all(|r| r.decisions.iter().all(|d| d.is_ok())));
            (p.exchange().state_hash(), t.elapsed().as_secs_f64())
        });
        assert_eq!(
            hash, base_hash,
            "pipelined state differs from the sequential baseline"
        );
        println!(
            "pipelined (4 threads, verify s+1 ∥ commit s, {replicas} replicas): {:>9.0} entries/s  ({:.2} s); state identical",
            total as f64 / dt,
            dt
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}
