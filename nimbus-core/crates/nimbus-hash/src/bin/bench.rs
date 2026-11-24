//! Merkle-root throughput: reference (1 core), streaming frontier (1 core), parallel (all cores).
use nimbus_hash::*;
use std::time::Instant;

fn main() {
    let m = 1 << 20;
    let items: Vec<[u8; 96]> = (0..m)
        .map(|i| {
            let mut v = [0u8; 96];
            v[..8].copy_from_slice(&(i as u64).to_be_bytes());
            v
        })
        .collect();
    let hashes = 2 * m - 1;
    let t = Instant::now();
    let r1 = merkle_root(BATCH, &items);
    let d1 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut f = Frontier::new(BATCH);
    for x in &items {
        f.push(x);
    }
    let r2 = f.root();
    let d2 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let r3 = par_merkle_root(BATCH, &items);
    let d3 = t.elapsed().as_secs_f64();
    assert!(r1 == r2 && r2 == r3);
    let th = rayon::current_num_threads();
    println!("m = {m} items ({hashes} SHA-384 hashes each)");
    println!(
        "reference : {:.1} ms  ({:.3} us/hash)",
        d1 * 1e3,
        d1 * 1e6 / hashes as f64
    );
    println!(
        "streaming : {:.1} ms  ({:.3} us/hash)",
        d2 * 1e3,
        d2 * 1e6 / hashes as f64
    );
    println!(
        "parallel  : {:.1} ms  ({:.3} us/hash wall, {th} threads, {:.2}x speed-up)",
        d3 * 1e3,
        d3 * 1e6 / hashes as f64,
        d1 / d3
    );
    // Streaming tail for a 4,096-op batch (Proposition R)
    let batch = &items[..4096];
    let mut tails: Vec<f64> = (0..2000)
        .map(|_| {
            let mut f = Frontier::new(BATCH);
            for x in &batch[..4095] {
                f.push(x);
            }
            let t = Instant::now();
            f.push(&batch[4095]);
            let _ = f.root();
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    tails.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "streaming tail, m = 4096: p50 {:.2} us, p99 {:.2} us (bound 13 hashes)",
        tails[1000], tails[1980]
    );
}
