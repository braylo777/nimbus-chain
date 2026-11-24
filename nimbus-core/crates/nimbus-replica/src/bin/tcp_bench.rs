//! Windowed replication over real loopback TCP, executed: slots of signed orders arrive every Δ_slot (paced in real
//! time); the engine (latency batching on a spin pool) replicates to two `ReplicaServer`s in threads of this
//! process, both required, over authenticated TCP (operator-signed shipments, replica-signed acknowledgements).
//! Links authenticated with Ed25519 signatures or with HMAC-SHA384; compared with the same engine and no replicas.
//! Journals on tmpfs (/dev/shm; the temporary directory where there is none). Reports release time − slot close.
//! Modes: no replicas; Ed25519 links; HMAC links; HMAC links with polled, spinning I/O (one engine I/O thread for all
//! replicas, spinning replica servers, the engine waiting for acknowledgements by spinning).
//! Env: TCP_SLOTS (2000), TCP_ENTRIES (8), TCP_SLOT_US (500), TCP_SPIN (1), TCP_REPLICAS (2), TCP_JSON (write JSON).
use ed25519_dalek::SigningKey;
use nimbus_journal::Journal;
use nimbus_match::{Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use nimbus_replica::*;
use std::net::TcpListener;
use std::time::{Duration, Instant};

const ACCOUNTS: u32 = 64;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let slots = env("TCP_SLOTS", 2000);
    let per = env("TCP_ENTRIES", 8) as u32;
    let delta = Duration::from_micros(env("TCP_SLOT_US", 500));
    let spin = env("TCP_SPIN", 1) as usize;
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
    let operator = SigningKey::from_bytes(&[9; 32]);
    let base = {
        // tmpfs on Linux; the system temporary directory elsewhere (macOS has no /dev/shm).
        let shm = std::path::Path::new("/dev/shm");
        let root = if shm.is_dir() {
            shm.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        root.join(format!("nimbus-tcp-bench-{}", std::process::id()))
    };
    let mut rows = Vec::new();
    let nrep = env("TCP_REPLICAS", 2) as u16;
    for (mode, replicas) in [
        ("none", 0u16),
        ("signatures", nrep),
        ("mac", nrep),
        ("mac-polled", nrep),
    ] {
        let polled = mode == "mac-polled";
        let d = base.join(mode);
        std::fs::create_dir_all(&d).unwrap();
        let cfg = Config {
            markets: 1,
            max_life: 1_000,
            fsync: true,
            min_batch: 1,
        };
        let (mut p, _) = Pipeline::open(&d, cfg, &genesis, operator.clone(), None).unwrap();
        p.use_spin_pool(spin);
        let mut servers = Vec::new();
        let mut streams: Vec<Box<dyn ReplicaStream>> = Vec::new();
        let mut polls: Vec<Box<dyn ReplicaPoll>> = Vec::new();
        for id in 0..replicas {
            let rd = d.join(format!("replica{id}"));
            std::fs::create_dir_all(&rd).unwrap();
            let key = SigningKey::from_bytes(&[60 + id as u8; 32]);
            let j = Journal::open(&rd.join("journal.bin"), usize::MAX)
                .unwrap()
                .0;
            let (sa, ea) = if mode.starts_with("mac") {
                (
                    Auth::Mac([30 + id as u8; 32]),
                    Auth::Mac([30 + id as u8; 32]),
                )
            } else {
                (
                    Auth::Signatures {
                        mine: key.clone(),
                        theirs: operator.verifying_key(),
                    },
                    Auth::Signatures {
                        mine: operator.clone(),
                        theirs: key.verifying_key(),
                    },
                )
            };
            let mut s = ReplicaServer::new(j, sa, id).unwrap();
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            servers.push(std::thread::spawn(move || {
                if polled {
                    s.serve_one_spinning(&l)
                } else {
                    s.serve_one(&l)
                }
            }));
            let r = TcpReplica::connect(addr, ea, id).unwrap();
            if polled {
                polls.push(Box::new(r.into_poll().unwrap()));
            } else {
                streams.push(Box::new(r));
            }
        }
        let wcfg = WindowConfig {
            depth: 64,
            ack_timeout: Duration::from_secs(2),
            max_inflight: 4096,
            spin: polled,
        };
        if polled {
            p.attach_polled_windowed(polls, replicas as usize, wcfg)
                .unwrap();
        } else {
            p.attach_streams_windowed(streams, replicas as usize, wcfg)
                .unwrap();
        }
        let start = Instant::now() + Duration::from_millis(5);
        let close = |s: u64| start + delta * s as u32;
        let mut lat = Vec::with_capacity(slots as usize);
        let mut last_lag = Duration::ZERO;
        for s in 1..=slots {
            while Instant::now() < close(s) {
                std::hint::spin_loop();
            }
            last_lag = Instant::now() - close(s);
            let released = p.submit_slot(s, &traffic[s as usize - 1]).unwrap();
            let now = Instant::now();
            lat.extend(
                released
                    .iter()
                    .map(|r| (now - close(r.slot)).as_secs_f64() * 1e3),
            );
        }
        let now = Instant::now();
        lat.extend(
            p.drain()
                .unwrap()
                .iter()
                .map(|r| (now - close(r.slot)).as_secs_f64() * 1e3),
        );
        assert_eq!(lat.len(), slots as usize);
        assert_eq!(p.live_replicas(), replicas as usize, "no replica dropped");
        lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (p50, p99) = (lat[lat.len() / 2], lat[lat.len() * 99 / 100]);
        let stable = last_lag < delta * 20;
        println!(
            "{mode:<10} {replicas} TCP replicas (all required): slot-close→release p50 {p50:.3} ms  p99 {p99:.3} ms  {}",
            if stable { "stable" } else { "UNSTABLE" }
        );
        rows.push(format!(
            "{{\"auth\": \"{mode}\", \"replicas\": {replicas}, \"p50_ms\": {p50:.4}, \"p99_ms\": {p99:.4}, \"stable\": {stable}}}"
        ));
        drop(p);
        for h in servers {
            h.join().unwrap().unwrap();
        }
        let engine = std::fs::read(d.join("journal.bin")).unwrap();
        for id in 0..replicas {
            assert_eq!(
                std::fs::read(d.join(format!("replica{id}/journal.bin"))).unwrap(),
                engine
            );
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    if let Ok(path) = std::env::var("TCP_JSON") {
        std::fs::write(
            path,
            format!(
                "{{\"slots\": {slots}, \"entries_per_slot\": {per}, \"slot_us\": {}, \"spin_workers\": {spin}, \"rows\": [{}]}}\n",
                delta.as_micros(),
                rows.join(", ")
            ),
        )
        .unwrap();
    }
}
