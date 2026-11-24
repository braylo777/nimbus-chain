//! Certifier cost, executed: (1) re-execution — the engine writes a journal of signed orders (fsync per slot); a
//! certifier's Replayer then re-derives every checkpoint from it, and its rate is compared with the engine's;
//! (2) certification — the cost of `Certifier::certify` per checkpoint (operator signature check, a durable record
//! of the slot, one Ed25519 signature); (3) restart — a snapshot's size and write time (fsync included), and the time
//! to reopen the certifier from it versus replaying the whole journal. Env: CERT_SLOTS (100), CERT_ENTRIES (2000 per
//! slot), CERT_JSON.
use ed25519_dalek::SigningKey;
use nimbus_bridge::*;
use nimbus_match::{Fees, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use std::time::Instant;

const ACCOUNTS: u32 = 1024;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let (slots, per) = (env("CERT_SLOTS", 100), env("CERT_ENTRIES", 2000) as u32);
    let keys: Vec<SigningKey> = (0..ACCOUNTS)
        .map(|a| {
            let mut s = [5u8; 32];
            s[..4].copy_from_slice(&a.to_be_bytes());
            SigningKey::from_bytes(&s)
        })
        .collect();
    let genesis = Genesis {
        accounts: (0..ACCOUNTS)
            .map(|a| (a, keys[a as usize].verifying_key()))
            .collect(),
        deposits: (0..4)
            .flat_map(|m| (0..ACCOUNTS).map(move |a| (m, a, 1u128 << 40, 1u128 << 60)))
            .collect(),
        fees: Fees {
            maker_bps: 2,
            taker_bps: 5,
            collector: u32::MAX,
            maker_rebate_bps: 0,
        },
        ..Genesis::default()
    };
    let cfg = Config {
        markets: 4,
        max_life: 1_000,
        fsync: true,
        min_batch: 16,
    };
    let mut nonce = vec![0u64; ACCOUNTS as usize];
    let mut x = 88172645463325252u64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let traffic: Vec<Vec<Vec<u8>>> = (1..=slots)
        .map(|slot| {
            (0..per)
                .map(|_| {
                    let a = (rnd() % ACCOUNTS as u64) as u32;
                    nonce[a as usize] += 1;
                    Entry::Order(SignedOrder::sign(
                        Intent {
                            market: (rnd() % 4) as u32,
                            acct: a,
                            side: if rnd() % 2 == 0 { Side::Bid } else { Side::Ask },
                            price: 990 + rnd() % 21,
                            qty: 1 + rnd() % 50,
                            tif: if rnd() % 5 == 0 { Tif::Ioc } else { Tif::Gtc },
                            nonce: nonce[a as usize] - 1,
                            expiry_slot: slot + 20,
                        },
                        &keys[a as usize],
                    ))
                    .to_bytes()
                })
                .collect()
        })
        .collect();
    let base = std::env::temp_dir().join(format!("nimbus-certify-bench-{}", std::process::id()));
    let operator = SigningKey::from_bytes(&[9; 32]);
    let total = (slots * per as u64) as f64;

    let (mut p, _) = Pipeline::open(
        &base.join("engine"),
        cfg.clone(),
        &genesis,
        operator.clone(),
        None,
    )
    .unwrap();
    let t = Instant::now();
    let refs: Vec<(u64, &[Vec<u8>])> = traffic
        .iter()
        .enumerate()
        .map(|(i, s)| (i as u64 + 1, s.as_slice()))
        .collect();
    let cks: Vec<Checkpoint> = p
        .process_slots(&refs)
        .unwrap()
        .iter()
        .filter_map(|r| r.checkpoint)
        .collect();
    let engine = total / t.elapsed().as_secs_f64();
    drop(p);

    std::fs::create_dir_all(base.join("cert")).unwrap();
    std::fs::copy(
        base.join("engine/journal.bin"),
        base.join("cert/journal.bin"),
    )
    .unwrap();
    let t = Instant::now();
    let mut c = Certifier::open(
        &base.join("cert"),
        cfg.clone(),
        &genesis,
        operator.verifying_key(),
        SigningKey::from_bytes(&[70; 32]),
        0,
    )
    .unwrap();
    let replay = total / t.elapsed().as_secs_f64();
    let mut per_ck: Vec<f64> = cks
        .iter()
        .map(|ck| {
            let t = Instant::now();
            c.certify(ck)
                .expect("the certifier reproduces every checkpoint");
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    per_ck.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let full_open_ms = total / replay * 1e3;
    let t = Instant::now();
    c.snapshot_now().unwrap();
    let snap_write_ms = t.elapsed().as_secs_f64() * 1e3;
    let snap_bytes = std::fs::metadata(base.join("cert/snapshot.bin"))
        .unwrap()
        .len();
    drop(c);
    let t = Instant::now();
    let c = Certifier::open(
        &base.join("cert"),
        cfg,
        &genesis,
        operator.verifying_key(),
        SigningKey::from_bytes(&[70; 32]),
        0,
    )
    .unwrap();
    let resume_ms = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(c.resumed_from(), Some(slots));
    let (p50, p99) = (per_ck[per_ck.len() / 2], per_ck[per_ck.len() * 99 / 100]);
    println!("engine (pipelined, 4 threads, fsync per slot): {engine:>9.0} entries/s");
    println!("certifier re-execution (open: journal verify + replay, 4 threads): {replay:>9.0} entries/s ({:.2}× the engine)", replay / engine);
    println!("certify per checkpoint: p50 {p50:.0} µs, p99 {p99:.0} µs ({} checkpoints, all reproduced and signed)", cks.len());
    println!("restart: full replay {full_open_ms:.0} ms; snapshot {snap_bytes} B written in {snap_write_ms:.1} ms, resume from it {resume_ms:.1} ms");
    if let Ok(path) = std::env::var("CERT_JSON") {
        std::fs::write(
            path,
            format!("{{\"slots\": {slots}, \"entries_per_slot\": {per}, \"engine_per_s\": {engine:.0}, \"replay_per_s\": {replay:.0}, \"certify_p50_us\": {p50:.1}, \"certify_p99_us\": {p99:.1}, \"full_open_ms\": {full_open_ms:.1}, \"snapshot_bytes\": {snap_bytes}, \"snapshot_write_ms\": {snap_write_ms:.2}, \"resume_ms\": {resume_ms:.2}}}\n"),
        )
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(&base);
}
