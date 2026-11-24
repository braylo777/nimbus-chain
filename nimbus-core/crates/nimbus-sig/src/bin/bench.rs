//! Signature verification cost per item: single vs `verify_all` (batched, all cores), for all-valid input and for
//! adversarial mixes (one bad signature per batch, 10 % bad, all bad — an invalid-signature flood).
use ed25519_dalek::{Signer, SigningKey};
use nimbus_sig::{verify, verify_all, verify_all_with, verify_batch, CheckedKey, Item, SpinPool};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

fn main() {
    let mut rng = StdRng::seed_from_u64(7);
    let keys: Vec<SigningKey> = (0..4096)
        .map(|_| SigningKey::from_bytes(&rng.gen()))
        .collect();
    let n = 20_000usize;
    let base: Vec<Item> = (0..n)
        .map(|i| {
            let k = &keys[rng.gen_range(0..keys.len())];
            let mut msg = [0u8; 48];
            msg[..8].copy_from_slice(&(i as u64).to_be_bytes());
            Item {
                key: CheckedKey::new(k.verifying_key().to_bytes()).unwrap(),
                msg,
                sig: k.sign(&msg).to_bytes(),
            }
        })
        .collect();
    let t = Instant::now();
    let ok = base
        .iter()
        .filter(|it| verify(&it.key, &it.msg, &it.sig))
        .count();
    let single = t.elapsed().as_secs_f64() / n as f64 * 1e6;
    assert_eq!(ok, n);
    println!("single verification (1 thread)               : {single:6.1} µs/signature");
    let threads = rayon::current_num_threads();
    for (label, bad_every) in [
        ("all valid", 0usize),
        ("1 bad per 5,000", 5_000),
        ("10 % bad", 10),
        ("all bad (flood)", 1),
    ] {
        let mut items = base.clone();
        let mut want = 0;
        for (i, it) in items.iter_mut().enumerate() {
            if bad_every > 0 && i % bad_every == 0 {
                it.sig[40] ^= 1;
            } else {
                want += 1;
            }
        }
        let t = Instant::now();
        let got = verify_all(&items).iter().filter(|&&b| b).count();
        let per = t.elapsed().as_secs_f64() / n as f64 * 1e6;
        assert_eq!(got, want);
        println!(
            "verify_all, {label:<16} ({threads} threads)   : {per:6.1} µs/signature wall = {:5.1} µs CPU ({:.2}× single)",
            per * threads as f64,
            per * threads as f64 / single
        );
    }
    // Batch-size sweep (feeds the engine latency model in the paper, §6.6): wall time to verify one batch of n.
    let mut rows = Vec::new();
    for n in [1usize, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096] {
        let reps = (20_000 / n).max(3);
        let mut samples: Vec<f64> = (0..reps)
            .map(|r| {
                let chunk = &base[(r * n) % (base.len() - n)..][..n];
                let t = Instant::now();
                assert!(verify_all(chunk).iter().all(|&b| b));
                t.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (p50, p99) = (
            samples[samples.len() / 2],
            samples[samples.len() * 99 / 100],
        );
        println!("batch {n:>5} on {threads} threads: p50 {p50:8.1} µs, p99 {p99:8.1} µs ({:.1} µs/signature)", p50 / n as f64);
        rows.push(format!(
            "{{\"n\":{n},\"threads\":{threads},\"p50_us\":{p50:.1},\"p99_us\":{p99:.1}}}"
        ));
    }
    if let Ok(path) = std::env::var("SIG_SWEEP_JSON") {
        std::fs::write(path, format!("[{}]", rows.join(","))).unwrap();
    }

    // Small-slot dispatch: 8 signatures (one 0.25–0.5 ms slot at 16–32 entries/ms), arriving after an idle gap, as in
    // a real-time slot loop. Rayon workers sleep between slots; a spin pool's do not.
    println!("\n8 signatures after an idle gap (p50 / p99, µs):");
    let eight: Vec<Item> = base[..8].to_vec();
    let pool = SpinPool::new(threads.saturating_sub(1).max(1));
    let mut lat = Vec::new();
    for gap_us in [0u64, 250, 1000] {
        let mut run = |name: &str, f: &dyn Fn() -> bool| {
            let mut v: Vec<f64> = (0..400)
                .map(|_| {
                    let t = Instant::now();
                    while t.elapsed() < Duration::from_micros(gap_us) {
                        std::hint::spin_loop();
                    }
                    let t = Instant::now();
                    assert!(f());
                    t.elapsed().as_secs_f64() * 1e6
                })
                .collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let (p50, p99) = (v[200], v[396]);
            println!("  gap {gap_us:>4} µs  {name:<34} {p50:7.0} / {p99:7.0}");
            lat.push(format!("{{\"gap_us\":{gap_us},\"method\":\"{name}\",\"p50_us\":{p50:.1},\"p99_us\":{p99:.1}}}"));
        };
        run("one batch, one core", &|| verify_batch(&eight));
        run("rayon, min_batch 1", &|| {
            verify_all_with(&eight, 1).iter().all(|&b| b)
        });
        run("spin pool", &|| pool.verify_all(&eight).iter().all(|&b| b));
    }
    if let Ok(path) = std::env::var("SIG_LATENCY_JSON") {
        std::fs::write(path, format!("[{}]", lat.join(","))).unwrap();
    }
}
