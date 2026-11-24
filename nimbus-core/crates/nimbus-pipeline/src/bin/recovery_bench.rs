//! Engine recovery, executed: the engine processes S slots of E signed orders (fsync per slot) with a background
//! snapshot every K slots, then is reopened (a) from its newest snapshot and (b) from genesis. Reported: the per-slot
//! time of slots that took a snapshot against those that did not (the engine pays only for encoding), the cost of a
//! synchronous snapshot (encode + write + fsync), the snapshot size, and both restart times.
//! Env: REC_SLOTS (300), REC_ENTRIES (2000), REC_EVERY (50), REC_JSON.
use ed25519_dalek::SigningKey;
use nimbus_match::{Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use rayon::prelude::*;
use std::time::Instant;

const ACCOUNTS: u32 = 4096;
const MARKETS: u32 = 16;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p) as usize]
}

fn main() {
    let (slots, per, every) = (
        env("REC_SLOTS", 300),
        env("REC_ENTRIES", 2000),
        env("REC_EVERY", 50),
    );
    let keys: Vec<SigningKey> = (0..ACCOUNTS)
        .map(|a| {
            let mut s = [3u8; 32];
            s[..4].copy_from_slice(&a.to_be_bytes());
            SigningKey::from_bytes(&s)
        })
        .collect();
    let genesis = Genesis {
        accounts: (0..ACCOUNTS)
            .map(|a| (a, keys[a as usize].verifying_key()))
            .collect(),
        deposits: (0..MARKETS)
            .flat_map(|m| (0..ACCOUNTS).map(move |a| (m, a, 1u128 << 40, 1u128 << 60)))
            .collect(),
        ..Genesis::default()
    };
    let cfg = Config {
        markets: MARKETS,
        max_life: 10_000,
        fsync: true,
        min_batch: 16,
    };
    // Orders: prices around 1,000 ticks, 80 % rest (the book grows), nonces sequential per account.
    let mut x = 0x9E3779B97F4A7C15u64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut nonce = vec![0u64; ACCOUNTS as usize];
    let intents: Vec<Vec<Intent>> = (1..=slots)
        .map(|slot| {
            (0..per)
                .map(|_| {
                    let a = (rnd() % ACCOUNTS as u64) as u32;
                    nonce[a as usize] += 1;
                    Intent {
                        market: (rnd() % MARKETS as u64) as u32,
                        acct: a,
                        side: if rnd() % 2 == 0 { Side::Bid } else { Side::Ask },
                        price: 980 + rnd() % 41,
                        qty: 1 + rnd() % 50,
                        tif: if rnd() % 5 == 0 { Tif::Ioc } else { Tif::Gtc },
                        nonce: nonce[a as usize] - 1,
                        expiry_slot: slot + 5_000,
                    }
                })
                .collect()
        })
        .collect();
    let traffic: Vec<Vec<Vec<u8>>> = intents
        .par_iter()
        .map(|s| {
            s.iter()
                .map(|i| Entry::Order(SignedOrder::sign(*i, &keys[i.acct as usize])).to_bytes())
                .collect()
        })
        .collect();
    let base = std::env::temp_dir().join(format!("nimbus-recovery-bench-{}", std::process::id()));
    let (d, full) = (base.join("engine"), base.join("full"));
    let operator = SigningKey::from_bytes(&[9; 32]);
    let (mut p, _) = Pipeline::open(&d, cfg.clone(), &genesis, operator.clone(), None).unwrap();
    // REC_FOLLOW=1: the engine takes no snapshots; a SnapshotFollower thread re-executes its journal and writes them.
    let follow = std::env::var("REC_FOLLOW").is_ok();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let follower = follow.then(|| {
        let (d, g, c, stop) = (d.clone(), genesis.clone(), cfg.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut f = SnapshotFollower::new(&d, c, &g).unwrap();
            let (mut last_snap, mut written) = (0u64, 0u32);
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                f.catch_up().unwrap();
                if f.last_slot().unwrap_or(0) >= last_snap + every {
                    f.snapshot().unwrap();
                    last_snap = f.last_slot().unwrap_or(0);
                    written += 1;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let lag_slot = f.last_slot().unwrap_or(0);
            f.catch_up().unwrap();
            f.snapshot().unwrap();
            (written + 1, lag_slot)
        })
    });
    if !follow {
        p.set_snapshot_every(every);
    }
    let (mut with, mut without, mut enc, mut all) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (i, subs) in traffic.iter().enumerate() {
        let slot = i as u64 + 1;
        let t = Instant::now();
        let r = p.process_slot(slot, subs).unwrap();
        let ms = t.elapsed().as_secs_f64() * 1e3;
        all.push(ms);
        if slot.is_multiple_of(every) {
            with.push(ms);
            enc.push(r.timings.snapshot.as_secs_f64() * 1e3);
        } else {
            without.push(ms)
        }
    }
    let open_orders: usize = p.exchange().markets.iter().map(|m| m.open_orders()).sum();
    let last = p.latest_checkpoint().unwrap();
    let (mut sync_ms, mut written, mut lag) = (0.0, 0, 0);
    if let Some(h) = follower {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (w, at) = h.join().unwrap();
        written = w;
        lag = slots - at;
    } else {
        p.flush_snapshots().unwrap();
        let t = Instant::now();
        p.snapshot_now().unwrap();
        sync_ms = t.elapsed().as_secs_f64() * 1e3;
    }
    let bytes = std::fs::metadata(d.join("snapshot.bin")).unwrap().len();
    drop(p);
    std::fs::create_dir_all(&full).unwrap();
    for name in ["journal.bin", "checkpoints.bin"] {
        std::fs::copy(d.join(name), full.join(name)).unwrap();
    }
    let t = Instant::now();
    let (_, r) = Pipeline::open(&d, cfg.clone(), &genesis, operator.clone(), Some(&last)).unwrap();
    let resume_ms = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(r.resumed_from, Some(slots));
    let t = Instant::now();
    let (_, r2) = Pipeline::open(&full, cfg, &genesis, operator, Some(&last)).unwrap();
    let full_ms = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(r2.resumed_from, None);
    let (w50, w99) = (pct(&mut with, 0.5), pct(&mut with, 0.99));
    let (o50, o99) = (pct(&mut without, 0.5), pct(&mut without, 0.99));
    let e50 = pct(&mut enc, 0.5);
    let (a50, a99, amax) = (pct(&mut all, 0.5), pct(&mut all, 0.99), pct(&mut all, 1.0));
    let mode = if follow { "follower" } else { "engine" };
    println!("{} slots × {per} orders, {open_orders} orders resting at the end, snapshots by the {mode} every {every} slots", slots);
    println!("slot time, all slots: p50 {a50:.2} ms, p99 {a99:.2} ms, max {amax:.2} ms");
    if follow {
        println!("follower: {written} snapshots; {lag} slots behind when the engine stopped");
    } else {
        println!("slot time: with a snapshot p50 {w50:.2} ms (max {w99:.2}), of which encoding {e50:.2} ms; without p50 {o50:.2} ms (p99 {o99:.2})");
        println!("synchronous snapshot (encode + write + fsync): {sync_ms:.1} ms for {bytes} B");
    }
    println!(
        "restart: from genesis {full_ms:.0} ms ({} records), from the snapshot {resume_ms:.1} ms",
        r2.records
    );
    if let Ok(path) = std::env::var("REC_JSON") {
        std::fs::write(path, format!(
            "{{\"slots\": {slots}, \"entries_per_slot\": {per}, \"every\": {every}, \"open_orders\": {open_orders}, \"snapshot_bytes\": {bytes}, \"mode\": \"{mode}\", \"slot_ms_p50\": {a50:.3}, \"slot_ms_p99\": {a99:.3}, \"slot_ms_max\": {amax:.3}, \"follower_snapshots\": {written}, \"follower_lag_slots\": {lag}, \"slot_ms_with_snapshot_p50\": {w50:.3}, \"slot_ms_with_snapshot_max\": {w99:.3}, \"encode_ms_p50\": {e50:.3}, \"slot_ms_without_p50\": {o50:.3}, \"slot_ms_without_p99\": {o99:.3}, \"sync_snapshot_ms\": {sync_ms:.2}, \"full_open_ms\": {full_ms:.1}, \"resume_ms\": {resume_ms:.2}}}\n")).unwrap();
    }
    let _ = std::fs::remove_dir_all(&base);
}
