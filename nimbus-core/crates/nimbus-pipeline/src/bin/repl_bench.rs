//! Replicated acknowledgement latency, executed: slots arrive every Δ_slot (paced in real time); the engine commits
//! with two journal replicas (both required) behind an emulated link that delays every batch by a round trip `rtt`.
//! Blocking replication (`process_slot`) waits inside the commit; windowed replication (`submit_slot`) ships and keeps
//! going. Journals live on tmpfs (/dev/shm; the temporary directory where there is none) so that the flush is not the
//! variable under test.
//! Reported per (mode, rtt): p50 / p99 of release time − slot close, and whether the backlog stayed bounded.
//! The emulated link is pipelined (delay counted from the ship time, `Replica::replicate_shipped`).
//! Verification runs on a spin pool (`REPL_SPIN` workers, default 1) in latency mode. The link sleeps for the round
//! trip, so the delay achieved (reported) exceeds the nominal one by the timer slack.
//! Env: REPL_SLOTS (default 2000), REPL_ENTRIES (entries per slot, default 8), REPL_SLOT_US (default 500),
//! REPL_SPIN, REPL_JSON (write results as JSON).
use ed25519_dalek::SigningKey;
use nimbus_journal::{Anchor, Journal};
use nimbus_match::{Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ACCOUNTS: u32 = 64;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// (journal, nominal round trip, (total µs of delay achieved, calls))
struct Link(Journal, Duration, Arc<(AtomicU64, AtomicU64)>);
impl Replica for Link {
    fn anchor(&self) -> Anchor {
        self.0.anchor()
    }
    fn replicate(&mut self, from: &Anchor, bytes: &[u8]) -> Result<Anchor, String> {
        self.replicate_shipped(from, bytes, Instant::now())
    }
    /// A pipelined link: the batch reaches the replica and its acknowledgement returns one round trip after it was
    /// shipped, however many batches are in flight; the replica applies batches one at a time.
    fn replicate_shipped(
        &mut self,
        from: &Anchor,
        bytes: &[u8],
        t: Instant,
    ) -> Result<Anchor, String> {
        // The round trip is spent on the wire; the replica's own write+flush adds to it.
        if let Some(left) = self.1.checked_sub(t.elapsed()) {
            std::thread::sleep(left);
        }
        let achieved = t.elapsed();
        self.2
             .0
            .fetch_add(achieved.as_micros() as u64, Ordering::Relaxed);
        self.2 .1.fetch_add(1, Ordering::Relaxed);
        self.0.replicate(from, bytes).map_err(|e| format!("{e:?}"))
    }
}

fn quantile(v: &mut [f64], q: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 * q) as usize).min(v.len() - 1)]
}

fn main() {
    let slots = env("REPL_SLOTS", 2000);
    let per = env("REPL_ENTRIES", 8) as u32;
    let delta = Duration::from_micros(env("REPL_SLOT_US", 500));
    let keys: Vec<SigningKey> = (0..ACCOUNTS)
        .map(|a| {
            let mut s = [7u8; 32];
            s[..4].copy_from_slice(&a.to_be_bytes());
            SigningKey::from_bytes(&s)
        })
        .collect();
    let genesis = Genesis {
        accounts: (0..ACCOUNTS)
            .map(|a| (a, keys[a as usize].verifying_key()))
            .collect(),
        deposits: (0..ACCOUNTS)
            .map(|a| (0, a, 1u128 << 40, 1u128 << 60))
            .collect(),
        ..Genesis::default()
    };
    // Pre-signed traffic: crossing orders at one price, so most entries fill.
    let mut nonce = vec![0u64; ACCOUNTS as usize];
    let traffic: Vec<Vec<Vec<u8>>> = (1..=slots)
        .map(|slot| {
            (0..per)
                .map(|i| {
                    let a = ((slot as u32) * per + i) % ACCOUNTS;
                    nonce[a as usize] += 1;
                    Entry::Order(SignedOrder::sign(
                        Intent {
                            market: 0,
                            acct: a,
                            side: if i % 2 == 0 { Side::Bid } else { Side::Ask },
                            price: 1_000,
                            qty: 1,
                            tif: Tif::Gtc,
                            nonce: nonce[a as usize] - 1,
                            expiry_slot: slot + 500,
                        },
                        &keys[a as usize],
                    ))
                    .to_bytes()
                })
                .collect()
        })
        .collect();
    let base = {
        // tmpfs on Linux; the system temporary directory elsewhere (macOS has no /dev/shm).
        let shm = std::path::Path::new("/dev/shm");
        let root = if shm.is_dir() {
            shm.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        root.join(format!("nimbus-repl-{}", std::process::id()))
    };
    let mut rows = Vec::new();
    let spin = env("REPL_SPIN", 1) as usize;
    for rtt_us in [0u64, 100, 200, 300, 500, 800] {
        for windowed in [false, true] {
            let d = base.join(format!("{rtt_us}-{windowed}"));
            let cfg = Config {
                markets: 1,
                max_life: 1_000,
                fsync: true,
                min_batch: 1,
            };
            let (mut p, _) =
                Pipeline::open(&d, cfg, &genesis, SigningKey::from_bytes(&[9; 32]), None).unwrap();
            p.use_spin_pool(spin);
            let achieved = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
            let set: Vec<Box<dyn Replica>> = (0..2)
                .map(|i| {
                    let j = Journal::open(&d.join(format!("replica{i}.bin")), usize::MAX)
                        .unwrap()
                        .0;
                    Box::new(Link(j, Duration::from_micros(rtt_us), achieved.clone()))
                        as Box<dyn Replica>
                })
                .collect();
            if windowed {
                p.attach_replicas_windowed(set, 2, 64).unwrap();
            } else {
                p.attach_replicas(set, 2).unwrap();
            }
            let start = Instant::now() + Duration::from_millis(5);
            let close = |s: u64| start + delta * s as u32;
            let mut lat = Vec::with_capacity(slots as usize);
            let mut backlog_max = Duration::ZERO;
            let mut last_lag = Duration::ZERO;
            let mut tim = Timings::default();
            let mut wall = Duration::ZERO;
            for s in 1..=slots {
                // Slot s closes at start + sΔ; the engine may start it no earlier (it may be later if behind).
                while Instant::now() < close(s) {
                    std::hint::spin_loop();
                }
                last_lag = Instant::now() - close(s);
                backlog_max = backlog_max.max(last_lag);
                let subs = &traffic[s as usize - 1];
                let t0 = Instant::now();
                let released = if windowed {
                    p.submit_slot(s, subs).unwrap()
                } else {
                    vec![p.process_slot(s, subs).unwrap()]
                };
                let now = Instant::now();
                wall += now - t0;
                for r in released {
                    tim.add(&r.timings);
                    lat.push((now - close(r.slot)).as_secs_f64() * 1e3);
                }
            }
            if windowed {
                let now = Instant::now();
                for r in p.drain().unwrap() {
                    lat.push((now - close(r.slot)).as_secs_f64() * 1e3);
                }
            }
            let (p50, p99) = (quantile(&mut lat, 0.5), quantile(&mut lat, 0.99));
            let us = |d: Duration| d.as_secs_f64() * 1e6 / slots as f64;
            println!(
                "    per slot: engine call {:.0} µs | verify {:.0} admit {:.0} commit {:.0} (journal {:.0}, match {:.0}) ckpt {:.0} expire {:.0}",
                us(wall), us(tim.verify), us(tim.admit), us(tim.commit), us(tim.journal), us(tim.matching), us(tim.checkpoint), us(tim.expire)
            );
            // Latency of an entry arriving uniformly in its slot adds U(0, Δ) on top of the slot-close latency.
            let stable = last_lag < delta * 20;
            let link_us = achieved.0.load(Ordering::Relaxed) as f64
                / achieved.1.load(Ordering::Relaxed).max(1) as f64;
            println!(
                "rtt {rtt_us:>4} µs (achieved {link_us:.0})  {:<8}  slot-close→release p50 {p50:.3} ms  p99 {p99:.3} ms  max start lag {:.2} ms  {}",
                if windowed { "windowed" } else { "blocking" },
                backlog_max.as_secs_f64() * 1e3,
                if stable { "stable" } else { "UNSTABLE (backlog grows)" }
            );
            rows.push(format!(
                "{{\"rtt_us\": {rtt_us}, \"achieved_rtt_us\": {link_us:.1}, \"design\": \"{}\", \"p50_ms\": {p50:.4}, \"p99_ms\": {p99:.4}, \"max_start_lag_ms\": {:.4}, \"stable\": {stable}}}",
                if windowed { "windowed" } else { "blocking" },
                backlog_max.as_secs_f64() * 1e3
            ));
            drop(p);
            let _ = std::fs::remove_dir_all(&d);
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    if let Ok(path) = std::env::var("REPL_JSON") {
        let body = format!(
            "{{\"slots\": {slots}, \"entries_per_slot\": {per}, \"slot_us\": {}, \"spin_workers\": {spin}, \"replicas\": 2, \"need\": 2, \"rows\": [\n {}\n]}}\n",
            delta.as_micros(),
            rows.join(",\n ")
        );
        std::fs::write(path, body).unwrap();
    }
}
