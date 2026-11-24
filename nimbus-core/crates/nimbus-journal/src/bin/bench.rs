//! Journal append throughput at several fsync batch sizes.
use nimbus_journal::Journal;
use nimbus_match::{Side, Tif};
use nimbus_order::{Entry, Intent, SignedOrder};
use std::time::Instant;

fn main() {
    let o = Entry::Order(SignedOrder {
        intent: Intent {
            market: 1,
            acct: 1,
            side: Side::Bid,
            price: 100,
            qty: 1,
            tif: Tif::Gtc,
            nonce: 0,
            expiry_slot: 9,
        },
        pubkey: [1; 32],
        sig: [2; 64],
    });
    for sync_every in [1usize, 16, 256, 4096] {
        let p = std::env::temp_dir().join(format!("journal-bench-{sync_every}"));
        let _ = std::fs::remove_file(&p);
        let (mut j, _) = Journal::open(&p, sync_every).expect("open");
        let n = if sync_every == 1 { 2_000 } else { 100_000 };
        let t = Instant::now();
        for _ in 0..n {
            j.append(1, &o).expect("append");
        }
        j.sync().expect("sync");
        let dt = t.elapsed().as_secs_f64();
        println!(
            "fsync every {sync_every:5}: {n} records in {:.3} s = {:.0} records/s ({:.2} MB/s)",
            dt,
            n as f64 / dt,
            n as f64 * nimbus_journal::ORDER_RECORD_LEN as f64 / dt / 1e6
        );
        let _ = std::fs::remove_file(&p);
    }
    // Group-commit latency for a 1 ms slot's worth of orders (128 records ≈ 26 KB): write + fdatasync, 2,000 samples.
    let p = std::env::temp_dir().join("journal-bench-slot");
    let _ = std::fs::remove_file(&p);
    let (mut j, _) = Journal::open(&p, usize::MAX).expect("open");
    let group: Vec<&Entry> = (0..128).map(|_| &o).collect();
    let mut us: Vec<f64> = (0..2_000u64)
        .map(|s| {
            let t = Instant::now();
            j.append_batch(s, &group).expect("append");
            j.sync().expect("sync");
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    let raw = us.clone();
    us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |f: f64| us[((us.len() as f64 * f) as usize).min(us.len() - 1)];
    println!(
        "group commit, 128 records ({} B): p50 {:.0} µs, p99 {:.0} µs, p99.9 {:.0} µs, max {:.0} µs",
        128 * nimbus_journal::ORDER_RECORD_LEN,
        q(0.5),
        q(0.99),
        q(0.999),
        us[us.len() - 1]
    );
    if let Ok(path) = std::env::var("FSYNC_JSON") {
        let v: Vec<String> = raw.iter().map(|x| format!("{x:.1}")).collect();
        std::fs::write(path, format!("[{}]", v.join(","))).unwrap();
    }
    let _ = std::fs::remove_file(&p);
}
